import os
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
from tkinter import font as tkfont
import random
import hashlib
import base64
import binascii

# Алфавиты для шифрования
russian_upper = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
russian_lower = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
english_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
english_lower = "abcdefghijklmnopqrstuvwxyz"
digits = "0123456789"

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
    
    def setup_ui(self):
        self.root.title("🔐 Шифровальщик Данных и генератор паролей")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Настройка стилей
        style = ttk.Style()
        style.theme_use('clam')
        
        # Основной контейнер
        self.main_frame = ttk.Frame(self.root, padding=15)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Заголовок
        header = ttk.Label(
            self.main_frame, 
            text="Шифратор и Генератор Паролей", 
            font=('Helvetica', 16, 'bold')
        )
        header.pack(pady=(0, 15))
        
        # Вкладки
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Создаем вкладки
        self.create_encryption_tab()
        self.create_password_tab()
        self.create_document_tab()
        
        # Статус бар
        self.status_bar = ttk.Label(
            self.main_frame, 
            text="Готово", 
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))

    def ask_password(self, title, prompt):
        """Универсальный диалог ввода пароля с возможностью вставки из буфера"""
        top = tk.Toplevel(self.root)
        top.title(title)
        top.geometry("400x200")
        
        frame = ttk.Frame(top)
        frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=prompt).pack(pady=5)
        
        password_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        entry.pack(pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)
        
        def paste_from_clipboard():
            try:
                clipboard_text = self.root.clipboard_get()
                if clipboard_text:
                    password_var.set(clipboard_text)
            except:
                pass
        
        ttk.Button(btn_frame, text="Вставить из буфера", command=paste_from_clipboard).pack(side=tk.LEFT, padx=5)
        
        show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(btn_frame, text="Показать", variable=show_var,
                      command=lambda: entry.config(show="" if show_var.get() else "*")).pack(side=tk.LEFT, padx=5)
        
        result = None
        
        def on_ok():
            nonlocal result
            result = password_var.get()
            top.destroy()
        
        def on_cancel():
            nonlocal result
            result = None
            top.destroy()
        
        btn_frame2 = ttk.Frame(frame)
        btn_frame2.pack(pady=10)
        
        ttk.Button(btn_frame2, text="OK", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame2, text="Отмена", command=on_cancel).pack(side=tk.LEFT, padx=10)
        
        top.transient(self.root)
        top.grab_set()
        entry.focus_set()
        self.root.wait_window(top)
        
        return result

    def create_document_tab(self):
        """Вкладка для работы с текстовыми документами"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📄 Документы")
        
        # Выбор метода шифрования
        method_frame = ttk.LabelFrame(tab, text="Метод шифрования", padding=10)
        method_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.doc_cipher_method = tk.StringVar(value="base64")
        
        ttk.Radiobutton(
            method_frame, 
            text="Base64", 
            variable=self.doc_cipher_method, 
            value="base64"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Radiobutton(
            method_frame, 
            text="Двоичный код", 
            variable=self.doc_cipher_method, 
            value="binary"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Radiobutton(
            method_frame, 
            text="XOR", 
            variable=self.doc_cipher_method, 
            value="xor"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        # Текстовое поле для ввода
        input_frame = ttk.LabelFrame(tab, text="Содержимое документа", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.doc_text_input = scrolledtext.ScrolledText(
            input_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=12, 
            font=('Consolas', 12),
            padx=10, 
            pady=10
        )
        self.doc_text_input.pack(fill=tk.BOTH, expand=True)
        
        # Панель кнопок файлов
        file_btn_frame = ttk.Frame(tab)
        file_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            file_btn_frame, 
            text="📂 Открыть файл", 
            command=self.open_document
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            file_btn_frame, 
            text="💾 Сохранить как...", 
            command=self.save_document_as
        ).pack(side=tk.LEFT, padx=5)
        
        # Панель кнопок шифрования
        crypto_btn_frame = ttk.Frame(tab)
        crypto_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            crypto_btn_frame, 
            text="📋 Вставить пароль", 
            command=self.paste_password_to_doc
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            crypto_btn_frame, 
            text="🔒 Зашифровать", 
            command=self.encrypt_document
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            crypto_btn_frame, 
            text="🔓 Расшифровать", 
            command=self.decrypt_document
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            crypto_btn_frame, 
            text="🔄 Очистить", 
            command=self.clear_document
        ).pack(side=tk.LEFT, padx=5)

    def paste_password_to_doc(self):
        """Вставить пароль из буфера обмена в диалог шифрования документа"""
        try:
            password = self.root.clipboard_get()
            if password:
                # Создаем временное окно для вставки пароля
                top = tk.Toplevel(self.root)
                top.title("Вставка пароля")
                top.geometry("300x100")
                
                tk.Label(top, text="Пароль из буфера обмена:").pack(pady=5)
                entry = ttk.Entry(top)
                entry.insert(0, password)
                entry.pack(pady=5)
                
                def apply_password():
                    method = self.doc_cipher_method.get()
                    if method == "base64":
                        try:
                            encrypted_text = base64_cipher(self.doc_text_input.get("1.0", tk.END).strip(), encrypt=True)
                            self.doc_text_input.delete('1.0', tk.END)
                            self.doc_text_input.insert('1.0', encrypted_text)
                            self.show_status("Текст успешно зашифрован (Base64)!")
                        except Exception as e:
                            self.show_status(f"Ошибка шифрования: {e}", "error")
                    elif method == "binary":
                        try:
                            encrypted_text = binary_cipher(self.doc_text_input.get("1.0", tk.END).strip(), encrypt=True)
                            self.doc_text_input.delete('1.0', tk.END)
                            self.doc_text_input.insert('1.0', encrypted_text)
                            self.show_status("Текст успешно зашифрован (Двоичный код)!")
                        except Exception as e:
                            self.show_status(f"Ошибка шифрования: {e}", "error")
                    elif method == "xor":
                        encrypted_text = xor_cipher(self.doc_text_input.get("1.0", tk.END).strip(), entry.get())
                        self.doc_text_input.delete('1.0', tk.END)
                        self.doc_text_input.insert('1.0', encrypted_text)
                        self.show_status("Текст успешно зашифрован (XOR)!")
                    top.destroy()
                
                ttk.Button(top, text="Применить", command=apply_password).pack(pady=5)
        except Exception as e:
            self.show_status(f"Ошибка вставки пароля: {e}", "error")

    def open_document(self):
        """Открытие текстового файла"""
        filepath = filedialog.askopenfilename(
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if not filepath:
            return
            
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
                self.doc_text_input.delete('1.0', tk.END)
                self.doc_text_input.insert('1.0', content)
                self.show_status(f"Файл {os.path.basename(filepath)} успешно загружен")
        except Exception as e:
            self.show_status(f"Ошибка загрузки файла: {str(e)}", "error")

    def save_document_as(self):
        """Сохранение текстового файла"""
        content = self.doc_text_input.get('1.0', tk.END).strip()
        if not content:
            self.show_status("Нет содержимого для сохранения!", "warning")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )
        if not filepath:
            return
            
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(content)
                self.show_status(f"Файл {os.path.basename(filepath)} успешно сохранен")
        except Exception as e:
            self.show_status(f"Ошибка сохранения файла: {str(e)}", "error")

    def encrypt_document(self):
        """Шифрование содержимого документа"""
        content = self.doc_text_input.get('1.0', tk.END).strip()
        if not content:
            self.show_status("Нет содержимого для шифрования!", "warning")
            return
            
        method = self.doc_cipher_method.get()
        
        if method == "base64":
            self.base64_encrypt_doc(content)
        elif method == "binary":
            self.binary_encrypt_doc(content)
        elif method == "xor":
            self.xor_encrypt_doc(content)

    def decrypt_document(self):
        """Дешифрование содержимого документа"""
        content = self.doc_text_input.get('1.0', tk.END).strip()
        if not content:
            self.show_status("Нет содержимого для расшифрования!", "warning")
            return
            
        method = self.doc_cipher_method.get()
        
        if method == "base64":
            self.base64_decrypt_doc(content)
        elif method == "binary":
            self.binary_decrypt_doc(content)
        elif method == "xor":
            self.xor_decrypt_doc(content)

    def clear_document(self):
        """Очистка содержимого документа"""
        self.doc_text_input.delete('1.0', tk.END)
        self.show_status("Текстовое поле очищено")

    def base64_encrypt_doc(self, text):
        try:
            encrypted_text = base64_cipher(text, encrypt=True)
            self.doc_text_input.delete('1.0', tk.END)
            self.doc_text_input.insert('1.0', encrypted_text)
            self.show_status("Текст успешно зашифрован (Base64)!")
        except Exception as e:
            self.show_status(f"Ошибка шифрования: {e}", "error")

    def base64_decrypt_doc(self, text):
        try:
            decrypted_text = base64_cipher(text, encrypt=False)
            self.doc_text_input.delete('1.0', tk.END)
            self.doc_text_input.insert('1.0', decrypted_text)
            self.show_status("Текст успешно расшифрован (Base64)!")
        except Exception as e:
            self.show_status(f"Ошибка расшифрования: {e}", "error")

    def binary_encrypt_doc(self, text):
        try:
            encrypted_text = binary_cipher(text, encrypt=True)
            self.doc_text_input.delete('1.0', tk.END)
            self.doc_text_input.insert('1.0', encrypted_text)
            self.show_status("Текст успешно зашифрован (Двоичный код)!")
        except Exception as e:
            self.show_status(f"Ошибка шифрования: {e}", "error")

    def binary_decrypt_doc(self, text):
        try:
            decrypted_text = binary_cipher(text, encrypt=False)
            self.doc_text_input.delete('1.0', tk.END)
            self.doc_text_input.insert('1.0', decrypted_text)
            self.show_status("Текст успешно расшифрован (Двоичный код)!")
        except Exception as e:
            self.show_status(f"Ошибка расшифрования: {e}", "error")

    def xor_encrypt_doc(self, text):
        key = self.ask_password("Ввод ключа", "Введите ключ (любые символы):")
        if key and key != "":
            try:
                encrypted_text = xor_cipher(text, key)
                self.doc_text_input.delete('1.0', tk.END)
                self.doc_text_input.insert('1.0', encrypted_text)
                self.show_status("Текст успешно зашифрован (XOR)!")
            except Exception as e:
                self.show_status(f"Ошибка шифрования: {e}", "error")

    def xor_decrypt_doc(self, text):
        key = self.ask_password("Ввод ключа", "Введите ключ (любые символы):")
        if key and key != "":
            try:
                decrypted_text = xor_cipher(text, key)
                self.doc_text_input.delete('1.0', tk.END)
                self.doc_text_input.insert('1.0', decrypted_text)
                self.show_status("Текст успешно расшифрован (XOR)!")
            except Exception as e:
                self.show_status(f"Ошибка расшифрования: {e}", "error")

    def create_encryption_tab(self):
        """Вкладка для шифрования/дешифрования"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 Шифрование текста")
        
        # Выбор метода шифрования
        method_frame = ttk.LabelFrame(tab, text="Метод шифрования", padding=10)
        method_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.cipher_method = tk.StringVar(value="base64")
        
        ttk.Radiobutton(
            method_frame, 
            text="Base64", 
            variable=self.cipher_method, 
            value="base64"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Radiobutton(
            method_frame, 
            text="Двоичный код", 
            variable=self.cipher_method, 
            value="binary"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Radiobutton(
            method_frame, 
            text="XOR", 
            variable=self.cipher_method, 
            value="xor"
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        # Текстовое поле для ввода
        input_frame = ttk.LabelFrame(tab, text="Исходный текст", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.text_input = scrolledtext.ScrolledText(
            input_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=12, 
            font=('Consolas', 12),
            padx=10, 
            pady=10
        )
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # Панель кнопок
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="📋 Вставить текст", 
            command=self.paste_from_clipboard
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="📋 Вставить пароль", 
            command=self.paste_password_to_text
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="🔄 Очистить", 
            command=self.clear_text
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="🔒 Зашифровать", 
            command=self.encrypt_text
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="🔓 Расшифровать", 
            command=self.decrypt_text
        ).pack(side=tk.RIGHT, padx=5)

    def paste_password_to_text(self):
        """Вставить пароль из буфера обмена в диалог шифрования текста"""
        try:
            password = self.root.clipboard_get()
            if password:
                # Создаем временное окно для вставки пароля
                top = tk.Toplevel(self.root)
                top.title("Вставка пароля")
                top.geometry("300x100")
                
                tk.Label(top, text="Пароль из буфера обмена:").pack(pady=5)
                entry = ttk.Entry(top)
                entry.insert(0, password)
                entry.pack(pady=5)
                
                def apply_password():
                    method = self.cipher_method.get()
                    text = self.text_input.get("1.0", tk.END).strip()
                    if method == "base64":
                        try:
                            encrypted_text = base64_cipher(text, encrypt=True)
                            self.show_result("🔒 Зашифрованный текст (Base64)", encrypted_text)
                            self.show_status("Текст успешно зашифрован (Base64)!")
                        except Exception as e:
                            self.show_status(f"Ошибка шифрования: {e}", "error")
                    elif method == "binary":
                        try:
                            encrypted_text = binary_cipher(text, encrypt=True)
                            self.show_result("🔒 Зашифрованный текст (Двоичный код)", encrypted_text)
                            self.show_status("Текст успешно зашифрован (Двоичный код)!")
                        except Exception as e:
                            self.show_status(f"Ошибка шифрования: {e}", "error")
                    elif method == "xor":
                        encrypted_text = xor_cipher(text, entry.get())
                        self.show_result("🔒 Зашифрованный текст (XOR)", encrypted_text)
                        self.show_status("Текст успешно зашифрован (XOR)!")
                    top.destroy()
                
                ttk.Button(top, text="Применить", command=apply_password).pack(pady=5)
        except Exception as e:
            self.show_status(f"Ошибка вставки пароля: {e}", "error")

    def create_password_tab(self):
        """Вкладка для генерации паролей"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Генератор паролей")
        
        # Настройки генерации
        settings_frame = ttk.LabelFrame(tab, text="Настройки генерации", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Длина пароля
        ttk.Label(settings_frame, text="Длина пароля:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.length_var = tk.IntVar(value=16)
        ttk.Spinbox(
            settings_frame, 
            from_=8, 
            to=64, 
            textvariable=self.length_var, 
            width=5
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Типы символов
        self.upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            settings_frame, 
            text="Заглавные буквы (A-Z)", 
            variable=self.upper_var
        ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            settings_frame, 
            text="Строчные буквы (a-z)", 
            variable=self.lower_var
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            settings_frame, 
            text="Цифры (0-9)", 
            variable=self.digits_var
        ).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            settings_frame, 
            text="Спецсимволы (!@# и др.)", 
            variable=self.symbols_var
        ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Кнопка генерации
        ttk.Button(
            tab, 
            text="🎲 Сгенерировать пароль", 
            command=self.generate_password_gui
        ).pack(fill=tk.X, padx=5, pady=5)
        
        # Результат
        result_frame = ttk.LabelFrame(tab, text="Результат", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.password_var = tk.StringVar()
        ttk.Entry(
            result_frame, 
            textvariable=self.password_var, 
            font=('Consolas', 14), 
            state='readonly'
        ).pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            result_frame, 
            text="📋 Копировать пароль", 
            command=self.copy_password
        ).pack(fill=tk.X, padx=5, pady=5)
        
        # История паролей
        history_frame = ttk.LabelFrame(tab, text="История (последние 5)", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.history_list = tk.Listbox(
            history_frame, 
            height=5, 
            font=('Consolas', 12)
        )
        self.history_list.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(
            history_frame, 
            text="📋 Копировать выбранный", 
            command=self.copy_from_history
        ).pack(fill=tk.X, padx=5, pady=(5, 0))

    def encrypt_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            self.show_status("Введите текст для шифрования!", "warning")
            return
            
        method = self.cipher_method.get()
        
        if method == "base64":
            self.base64_encrypt(text)
        elif method == "binary":
            self.binary_encrypt(text)
        elif method == "xor":
            self.xor_encrypt(text)
    
    def decrypt_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            self.show_status("Введите текст для расшифрования!", "warning")
            return
            
        method = self.cipher_method.get()
        
        if method == "base64":
            self.base64_decrypt(text)
        elif method == "binary":
            self.binary_decrypt(text)
        elif method == "xor":
            self.xor_decrypt(text)
    
    def base64_encrypt(self, text):
        try:
            encrypted_text = base64_cipher(text, encrypt=True)
            self.show_result("🔒 Зашифрованный текст (Base64)", encrypted_text)
            self.show_status("Текст успешно зашифрован (Base64)!")
        except Exception as e:
            self.show_status(f"Ошибка шифрования: {e}", "error")

    def base64_decrypt(self, text):
        try:
            decrypted_text = base64_cipher(text, encrypt=False)
            self.show_result("🔓 Расшифрованный текст (Base64)", decrypted_text)
            self.show_status("Текст успешно расшифрован (Base64)!")
        except Exception as e:
            self.show_status(f"Ошибка расшифрования: {e}", "error")

    def binary_encrypt(self, text):
        try:
            encrypted_text = binary_cipher(text, encrypt=True)
            self.show_result("🔒 Зашифрованный текст (Двоичный код)", encrypted_text)
            self.show_status("Текст успешно зашифрован (Двоичный код)!")
        except Exception as e:
            self.show_status(f"Ошибка шифрования: {e}", "error")

    def binary_decrypt(self, text):
        try:
            decrypted_text = binary_cipher(text, encrypt=False)
            self.show_result("🔓 Расшифрованный текст (Двоичный код)", decrypted_text)
            self.show_status("Текст успешно расшифрован (Двоичный код)!")
        except Exception as e:
            self.show_status(f"Ошибка расшифрования: {e}", "error")

    def xor_encrypt(self, text):
        key = self.ask_password("Ввод ключа", "Введите ключ (любые символы):")
        if key and key != "":
            try:
                encrypted_text = xor_cipher(text, key)
                self.show_result("🔒 Зашифрованный текст (XOR)", encrypted_text)
                self.show_status("Текст успешно зашифрован (XOR)!")
            except Exception as e:
                self.show_status(f"Ошибка шифрования: {e}", "error")

    def xor_decrypt(self, text):
        key = self.ask_password("Ввод ключа", "Введите ключ (любые символы):")
        if key and key != "":
            try:
                decrypted_text = xor_cipher(text, key)
                self.show_result("🔓 Расшифрованный текст (XOR)", decrypted_text)
                self.show_status("Текст успешно расшифрован (XOR)!")
            except Exception as e:
                self.show_status(f"Ошибка расшифрования: {e}", "error")

    def generate_password_gui(self):
        chars = []
        if self.upper_var.get():
            chars.extend(string.ascii_uppercase)
        if self.lower_var.get():
            chars.extend(string.ascii_lowercase)
        if self.digits_var.get():
            chars.extend(string.digits)
        if self.symbols_var.get():
            chars.extend(string.punctuation)
            
        if not chars:
            self.show_status("Выберите хотя бы один тип символов!", "warning")
            return
            
        password = generate_password(self.length_var.get(), chars)
        self.password_var.set(password)
        
        # Добавляем в историю (максимум 5)
        self.history_list.insert(0, password)
        if self.history_list.size() > 5:
            self.history_list.delete(5)
        
        self.show_status(f"Сгенерирован пароль длиной {self.length_var.get()} символов")
    
    def show_result(self, title, text):
        result_window = tk.Toplevel(self.root)
        result_window.title(title)
        result_window.geometry("600x400")
        
        text_area = scrolledtext.ScrolledText(
            result_window, 
            wrap=tk.WORD, 
            font=('Consolas', 12),
            padx=10, 
            pady=10
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        
        text_area.insert(tk.END, text)
        text_area.config(state=tk.DISABLED)
        
        btn_frame = ttk.Frame(result_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="📋 Копировать", 
            command=lambda: self.copy_to_clipboard(text)
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            btn_frame, 
            text="Закрыть", 
            command=result_window.destroy
        ).pack(side=tk.RIGHT)
    
    def copy_password(self):
        password = self.password_var.get()
        if password:
            self.copy_to_clipboard(password)
            self.show_status("Пароль скопирован в буфер обмена!")
        else:
            self.show_status("Нет пароля для копирования!", "warning")
    
    def copy_from_history(self):
        selection = self.history_list.curselection()
        if selection:
            password = self.history_list.get(selection[0])
            self.copy_to_clipboard(password)
            self.show_status("Пароль скопирован в буфер обмена!")
        else:
            self.show_status("Выберите пароль из списка!", "warning")
    
    def paste_from_clipboard(self):
        try:
            text = self.root.clipboard_get()
            self.text_input.insert(tk.END, text)
            self.show_status("Текст вставлен из буфера обмена")
        except Exception as e:
            self.show_status(f"Ошибка вставки: {e}", "error")
    
    def clear_text(self):
        self.text_input.delete("1.0", tk.END)
        self.show_status("Текстовое поле очищено")
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
    
    def show_status(self, message, status="info"):
        self.status_bar.config(text=message)
        if status == "error":
            self.status_bar.config(foreground="red")
        elif status == "warning":
            self.status_bar.config(foreground="orange")
        else:
            self.status_bar.config(foreground="green")

def base64_cipher(text, encrypt=True):
    """Кодирование/декодирование в Base64"""
    if encrypt:
        # Кодируем в Base64
        text_bytes = text.encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        return base64_bytes.decode('utf-8')
    else:
        # Декодируем из Base64
        try:
            base64_bytes = text.encode('utf-8')
            text_bytes = base64.b64decode(base64_bytes)
            return text_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("Некорректные данные Base64") from e

def binary_cipher(text, encrypt=True):
    """Кодирование/декодирование в двоичный код"""
    if encrypt:
        # Преобразуем текст в двоичный код
        binary_string = ""
        for char in text:
            # Получаем код символа и преобразуем в двоичное представление (8 бит)
            binary_char = format(ord(char), '08b')
            binary_string += binary_char + " "  # Добавляем пробел для читаемости
        return binary_string.strip()
    else:
        # Преобразуем двоичный код обратно в текст
        try:
            # Убираем лишние пробелы и разбиваем на группы по 8 бит
            binary_chars = text.split()
            text_string = ""
            for binary_char in binary_chars:
                # Преобразуем двоичную строку в число, затем в символ
                char_code = int(binary_char, 2)
                text_string += chr(char_code)
            return text_string
        except (ValueError, TypeError) as e:
            raise ValueError("Некорректный двоичный код") from e

def xor_cipher(text, key):
    """Шифрование XOR с заданным ключом"""
    key_bytes = key.encode()
    result = []
    for i, char in enumerate(text):
        key_char = key_bytes[i % len(key_bytes)]
        result_char = chr(ord(char) ^ key_char)
        result.append(result_char)
    return ''.join(result)

def generate_password(length=12, chars=None):
    """Генерация пароля с заданными символами"""
    if chars is None:
        chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
