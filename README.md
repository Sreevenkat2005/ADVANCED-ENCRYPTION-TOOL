# ADVANCED-ENCRYPTION-TOOL

*Company*: CODTECH IT SOLUTIONS

*NAME*: Sree venkat Ramanujula

*INTERN ID*:CT06DH1414

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURACTION*: 6 WEEKS

*MENTOR*: NEELA SANTOSH

---

### **Description**

The **AES-256 File Encryption & Decryption Tool** is a Python-based application designed to provide secure file handling through a simple and user-friendly **Streamlit interface**. It combines the power of **Advanced Encryption Standard (AES) with a 256-bit key** for robust data protection, and the simplicity of a web-based UI for accessibility and ease of use.

---

### **Core Functionality**

This tool allows users to **encrypt** sensitive files, rendering them unreadable to unauthorized individuals, and later **decrypt** them back to their original form using the correct password. The AES-256 algorithm is widely recognized as one of the most secure symmetric encryption methods, making it suitable for protecting confidential documents, personal records, or business files.

The encryption process involves generating a unique 32-byte key from the user’s password using the **PBKDF2** key derivation function with SHA-256 hashing. This ensures that even weak passwords become significantly stronger against brute-force attacks. Files are read in binary form, encrypted in chunks, and saved with a `.enc` extension. Decryption reverses the process, restoring the file’s original format.

---

### **Streamlit User Interface**

The **Streamlit** library transforms the encryption script into a clean, interactive UI without requiring HTML or JavaScript. Through the interface, users can:

* **Select a mode** (Encrypt or Decrypt) via a dropdown menu.
* **Upload a file** directly from their system.
* **Enter a password** for encryption or decryption.
* **Run the process** with a single click.
* **Download the output file** instantly after processing.

This design eliminates command-line complexity, making the tool accessible even to non-technical users.

---

### **Security Considerations**

* **AES-256** ensures high-level encryption security.
* **PBKDF2 with salt** strengthens password resistance against attacks.
* Files are processed entirely locally, so no data is uploaded to external servers.
* Random initialization vectors (IVs) are used to ensure different ciphertexts for the same file-password pair.

---

### **Use Cases**

* Protecting sensitive corporate documents.
* Encrypting personal photos, financial records, or legal files.
* Securing backups before storing them in cloud services.
* Sending confidential files via email or other channels safely.

---

### **Conclusion**

This tool offers a practical combination of **strong encryption** and **ease of use**. With the integration of **Streamlit**, users gain the benefits of a professional-grade encryption mechanism without needing command-line knowledge. Whether for personal, academic, or professional purposes, it ensures that **data privacy and security remain in the user’s hands**.

---

#Output

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/b777ca48-c809-4ca9-8925-903f03e3667c" />

#Demo Vid

https://github.com/user-attachments/assets/c536778a-5578-40d4-97b4-55c28361646b


