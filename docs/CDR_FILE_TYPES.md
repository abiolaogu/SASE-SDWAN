# CDR File Types

## Content Disarm & Reconstruct (CDR)

CDR removes all potentially malicious active content from files while preserving the usable content.

---

## Supported File Types

### PDF Documents

| Threat | Action |
|--------|--------|
| JavaScript | Remove |
| Embedded files | Remove |
| Form actions | Remove |
| Launch actions | Remove |
| URI actions | Sanitize |
| Annotations | Remove dangerous |
| XFA forms | Flatten |

**Output**: Flattened PDF with visual content only

---

### Microsoft Office

| Format | Threats Removed |
|--------|-----------------|
| `.docx` | VBA macros, external links, OLE objects, DDE |
| `.xlsx` | Macros, external connections, pivot sources |
| `.pptx` | Macros, embedded media, external links |

**Method**: Convert to PDF via LibreOffice (strips all active content)

---

### Images

| Format | Threats Removed |
|--------|-----------------|
| JPEG | EXIF metadata, embedded thumbnails |
| PNG | tEXt/iTXt chunks, ICC profiles |
| GIF | Application extensions |
| SVG | JavaScript, external references |
| WebP | Metadata |

**Method**: Decode then re-encode to strip metadata

---

### Archives

| Format | Handling |
|--------|----------|
| ZIP | Recursive scan, path validation |
| RAR | Extract and sanitize contents |
| 7z | Extract and sanitize contents |
| TAR.GZ | Extract and sanitize contents |

**Checks**:
- Zip bomb detection (compression ratio)
- Path traversal prevention (`../`)
- Nested archive depth limit (3 levels)
- Total extracted size limit (500MB)

---

### Blocked File Types

| Extension | Reason |
|-----------|--------|
| `.exe`, `.msi`, `.dll` | Windows executables |
| `.sh`, `.bash` | Shell scripts |
| `.bat`, `.cmd`, `.ps1` | Windows scripts |
| `.js`, `.vbs`, `.wsf` | Script files |
| `.jar`, `.class` | Java executables |
| `.dmg`, `.app` | macOS executables |
| `.elf`, `.so` | Linux executables |
| `.scr`, `.com` | Screensavers/COM files |
| `.hta`, `.mht` | HTML applications |
| `.iso`, `.img` | Disk images |

---

## Detection Methods

### Magic Bytes
```
PDF:  %PDF
ZIP:  50 4B 03 04
JPEG: FF D8 FF
PNG:  89 50 4E 47
GIF:  47 49 46 38
PE:   4D 5A (MZ)
ELF:  7F 45 4C 46
```

### MIME Type Validation
- Header declared type
- Extension matching
- Content analysis

---

## Processing Pipeline

```
Download Intercepted
        │
        ▼
┌───────────────────┐
│ Type Detection    │
│ (magic + MIME)    │
└───────┬───────────┘
        │
        ▼
┌───────────────────┐
│ Malware Scan      │
│ (ClamAV + YARA)   │
└───────┬───────────┘
        │
        ▼
┌───────────────────┐
│ CDR Processing    │
│ (type-specific)   │
└───────┬───────────┘
        │
        ▼
┌───────────────────┐
│ Output Validation │
│ (re-scan result)  │
└───────┬───────────┘
        │
        ▼
   Sanitized File
```

---

## Performance

| File Type | Avg Processing Time |
|-----------|---------------------|
| PDF (<10MB) | <500ms |
| Office (<10MB) | <2s |
| Image (<5MB) | <200ms |
| Archive (<50MB) | <5s |
