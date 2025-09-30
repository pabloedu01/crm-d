# core/storages.py

import os
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from vercel_blob import put, head, BlobError

@deconstructible
class VercelBlobStorage(Storage):
    """
    Custom storage backend for Vercel Blob Storage using the BLOB_READ_WRITE_TOKEN.
    """
    def _save(self, name, content):
        file_content = content.read()
        try:
            # A opção `access: 'public'` é crucial para que os arquivos sejam acessíveis.
            # O `addRandomSuffix: False` evita que a Vercel adicione um hash aleatório ao nome do arquivo.
            put(name, file_content, options={'access': 'public', 'addRandomSuffix': False})
        except BlobError as e:
            raise IOError(f"Failed to upload {name} to Vercel Blob: {e}")
        return name

    def _open(self, name, mode='rb'):
        # Método raramente usado para arquivos estáticos, mas necessário para compatibilidade.
        return ContentFile(b'', name=name)

    def url(self, name):
        """
        Retorna a URL pública do arquivo.
        Usa a variável de ambiente BLOB_URL fornecida pela Vercel.
        """
        blob_base_url = os.getenv('BLOB_URL')
        if not blob_base_url:
            raise ValueError("BLOB_URL environment variable not set. Make sure the Blob Store is connected.")
        
        # Garante que não haja barras duplas na URL final
        return f"{blob_base_url.rstrip('/')}/{name}"

    def exists(self, name):
        """
        Verifica se um arquivo existe no Vercel Blob.
        """
        try:
            # A função head usa a URL completa do arquivo para verificar a existência.
            head(self.url(name))
            return True
        except BlobError as e:
            if e.status_code == 404:
                return False
            raise e

    def listdir(self, path):
        # Não é necessário para o collectstatic funcionar.
        return [], []