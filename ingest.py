import os
import re
from langchain_text_splitters import RecursiveCharacterTextSplitter, MarkdownHeaderTextSplitter
from langchain_community.document_loaders import PyPDFLoader, TextLoader, DirectoryLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

def clean_markdown(text: str) -> str:
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)           # ảnh, badge
    text = re.sub(r'\[Back to top\].*?\n', '', text, flags=re.I)
    text = re.sub(r'<!--.*?-->', '', text, flags=re.S)    # html comment
    text = re.sub(r'\n{3,}', '\n\n', text)                 # thừa dòng trống
    return text.strip()


def load_pdf_docs(path, source_type):
    loader = DirectoryLoader(path, glob="**/*.pdf", loader_cls=PyPDFLoader)
    docs = loader.load()
    for d in docs:
        d.metadata["source_type"] = source_type
        d.metadata["file_type"] = "pdf"
    return docs


def load_md_docs(path, source_type):
    loader = DirectoryLoader(
        path,
        glob="**/*.md",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"},
    )   
    raw_docs = loader.load()

    headers_to_split_on = [("#", "h1"), ("##", "h2"), ("###", "h3")]
    md_header_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=headers_to_split_on,
        strip_headers=False,   # giữ heading trong content để LLM có ngữ cảnh khi trả lời
    )

    sections = []
    for d in raw_docs:
        cleaned = clean_markdown(d.page_content)
        if not cleaned:
            continue
        for sec in md_header_splitter.split_text(cleaned):
            # merge metadata gốc (đường dẫn file...) với metadata heading
            sec.metadata.update({
                "source": d.metadata.get("source", ""),
                "source_type": source_type,
                "file_type": "md",
            })
            sections.append(sec)
    return sections


if __name__ == "__main__":
    print("[*] Đang load tài liệu...")

    all_pdf_docs = []
    all_md_sections = []

    # Tự động lấy đường dẫn của thư mục chứa file ingest.py
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    for folder, stype in [
        ("knowledge_base/owasp", "owasp"),
        ("knowledge_base/playbooks", "playbook"),
        ("knowledge_base/mitre", "mitre"),
    ]:
        # Ghép đường dẫn tuyệt đối
        target_folder = os.path.join(BASE_DIR, folder)
        
        if not os.path.isdir(target_folder):
            print(f"[!] Không tìm thấy thư mục: {target_folder}, bỏ qua.")
            continue
        all_pdf_docs += load_pdf_docs(target_folder, stype)
        all_md_sections += load_md_docs(target_folder, stype)

    if not all_pdf_docs and not all_md_sections:
        print("[!] Không tìm thấy tài liệu nào. Hãy check lại thư mục knowledge_base.")
        exit()

    print(f"[*] Đã load {len(all_pdf_docs)} PDF docs, {len(all_md_sections)} MD sections. Đang chunking...")

    char_splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=150,
        separators=["\n\n", "\n", ". ", " "]
    )

    pdf_chunks = char_splitter.split_documents(all_pdf_docs)
    md_chunks = char_splitter.split_documents(all_md_sections)
    chunks = pdf_chunks + md_chunks

    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
    )
    
    print("[*] Đang lưu vào ChromaDB...")
    
    # Lưu ChromaDB vào đúng thư mục Code
    db_path = os.path.join(BASE_DIR, "chroma_db")
    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=db_path,
        collection_name="soc_knowledge"
    )
    print(f"[+] Hoàn tất! Ingested {len(chunks)} chunks vào ChromaDB (PDF: {len(pdf_chunks)}, MD: {len(md_chunks)}).")