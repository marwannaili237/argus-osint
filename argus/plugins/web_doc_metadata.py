"""Document metadata extraction plugin."""
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class WebDocMetadataPlugin(BasePlugin):
    name = "web_doc_metadata"
    target_types = ["url"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        """Attempt to extract metadata from document URLs (PDF, DOCX, XLSX, etc.).
        Fetches the document and reads metadata from the binary content."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    content_type = resp.headers.get("Content-Type", "")
                    content_length = int(resp.headers.get("Content-Length", 0))
                    content = await resp.read()
                    
                    result = {
                        "url": target,
                        "content_type": content_type,
                        "size_bytes": len(content),
                        "document_type": "unknown",
                    }

                    # PDF metadata extraction
                    if content_type == "application/pdf" or target.lower().endswith(".pdf"):
                        result["document_type"] = "PDF"
                        text = content[:content_length] if content_length > 0 else content[:100000]
                        # Try to extract PDF metadata from the raw bytes
                        pdf_text = text.decode("utf-8", errors="replace")
                        
                        # Look for common PDF metadata fields
                        import re
                        for field, pattern in [
                            ("title", r'/Title\s*\(([^)]*)\)'),
                            ("author", r'/Author\s*\(([^)]*)\)'),
                            ("subject", r'/Subject\s*\(([^)]*)\)'),
                            ("creator", r'/Creator\s*\(([^)]*)\)'),
                            ("producer", r'/Producer\s*\(([^)]*)\)'),
                            ("creation_date", r'/CreationDate\s*\(([^)]*)\)'),
                            ("mod_date", r'/ModDate\s*\(([^)]*)\)'),
                        ]:
                            m = re.search(pattern, pdf_text)
                            if m:
                                result[field] = m.group(1).strip()

                        # Try with pypdf if available
                        try:
                            import io
                            from pypdf import PdfReader
                            reader = PdfReader(io.BytesIO(content))
                            info = reader.metadata
                            if info:
                                result["title"] = info.get("/Title", result.get("title", ""))
                                result["author"] = info.get("/Author", result.get("author", ""))
                                result["subject"] = info.get("/Subject", result.get("subject", ""))
                                result["creator"] = info.get("/Creator", result.get("creator", ""))
                                result["producer"] = info.get("/Producer", result.get("producer", ""))
                                result["creation_date"] = str(info.get("/CreationDate", result.get("creation_date", "")))
                                result["mod_date"] = str(info.get("/ModDate", result.get("mod_date", "")))
                            result["page_count"] = len(reader.pages)
                        except ImportError:
                            pass

                    # Office document metadata (DOCX, XLSX, PPTX)
                    elif any(t in content_type for t in ["officedocument", "openxmlformats", "wordprocessingml", "spreadsheetml", "presentationml"]):
                        doc_type = "DOCX"
                        if "spreadsheet" in content_type:
                            doc_type = "XLSX"
                        elif "presentation" in content_type:
                            doc_type = "PPTX"
                        result["document_type"] = doc_type
                        
                        try:
                            import zipfile
                            import io
                            zf = zipfile.ZipFile(io.BytesIO(content))
                            if "docProps/core.xml" in zf.namelist():
                                core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                                for field, tag in [("title", "dc:title"), ("author", "dc:creator"), ("subject", "dc:subject")]:
                                    m = re.search(f"<{tag}>([^<]+)</{tag}>", core_xml)
                                    if m:
                                        result[field] = m.group(1)
                            if "docProps/app.xml" in zf.namelist():
                                app_xml = zf.read("docProps/app.xml").decode("utf-8", errors="replace")
                                m = re.search(r"<Application>([^<]+)</Application>", app_xml)
                                if m:
                                    result["software"] = m.group(1)
                            zf.close()
                        except Exception:
                            pass

                    # Image metadata
                    elif any(t in content_type for t in ["image/jpeg", "image/png", "image/gif", "image/webp"]):
                        result["document_type"] = content_type.split("/")[-1].upper()
                        try:
                            from PIL import Image
                            import io
                            img = Image.open(io.BytesIO(content))
                            result["width"] = img.width
                            result["height"] = img.height
                            result["format"] = img.format
                            result["mode"] = img.mode
                            exif = img._getexif() if hasattr(img, '_getexif') else None
                            if exif:
                                result["has_exif"] = True
                                result["exif_keys"] = list(exif.keys())[:20]
                        except ImportError:
                            pass

                    return PluginResult(plugin_name=self.name, status="success", data=result)

        except Exception as e:
            logger.error(f"Document metadata extraction failed: {e}")
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))
