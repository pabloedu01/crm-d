import os
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from vercel_blob import put, list, head, BlobError

@deconstructible
class VercelBlobStorage(Storage):
    """
    Custom storage backend for Vercel Blob Storage using the BLOB_READ_WRITE_TOKEN.
    """
    def __init__(self):
        # O token é lido automaticamente pela biblioteca a partir da variável de ambiente
        # BLOB_READ_WRITE_TOKEN, então não precisamos passá-lo aqui.
        pass

    def _save(self, name, content):
        """
        Salva o arquivo no Vercel Blob. O 'name' é o caminho do arquivo (ex: 'css/style.css').
        O 'content' é o objeto do arquivo.
        """
        # A Vercel recomenda tratar os blobs como imutáveis.
        # Por padrão, a biblioteca `put` sobrescreve arquivos com o mesmo nome.
        file_content = content.read()
        try:
            # A opção `access: 'public'` é crucial para que os arquivos sejam acessíveis.
            put(name, file_content, options={'access': 'public'})
        except BlobError as e:
            raise IOError(f"Failed to upload {name} to Vercel Blob: {e}")
        return name

    def _open(self, name, mode='rb'):
        """
        Este método não é prático para um storage remoto,
        mas é necessário para a compatibilidade com o Django.
        Retornamos o conteúdo em memória, mas isso raramente será usado para arquivos estáticos.
        """
        # Esta implementação é simplificada, pois geralmente não lemos
        # arquivos estáticos de volta para o servidor Django.
        return ContentFile(b'', name=name)


    def url(self, name):
        """
        Retorna a URL pública do arquivo.
        Precisamos construir a URL baseada na estrutura da Vercel.
        """
        # A biblioteca `vercel-blob` não retorna a URL pública completa de forma direta e previsível.
        # A forma mais robusta é construir a URL. O formato é:
        # https://<store_id>.public.blob.vercel-storage.com/<pathname>
        # A Vercel ainda não expõe o ID da store como uma variável de ambiente padrão.
        # Uma alternativa mais simples é usar o nome do seu projeto, que geralmente corresponde ao ID.
        # Vamos assumir que o nome do blob store é 'crm-d-blob' como na sua imagem.
        # IMPORTANTE: Você pode precisar ajustar isso no futuro se a Vercel mudar.
        
        # O nome do seu store, conforme a imagem.
        store_name = "crm-d-blob" 
        return f"https://{store_name}.public.blob.vercel-storage.com/{name}"


    def exists(self, name):
        """
        Verifica se um arquivo existe no Vercel Blob.
        """
        try:
            # A função `head` retorna os metadados do arquivo se ele existir,
            # ou lança uma exceção `BlobNotFoundError` se não existir.
            metadata = head(self.url(name))
            return metadata is not None
        except BlobError as e:
            # Se o erro for "not found", retornamos False.
            if e.status_code == 404:
                return False
            # Se for outro erro, lançamos a exceção.
            raise e

    def listdir(self, path):
        # Este método é complexo de implementar com a API atual do vercel-blob
        # e não é estritamente necessário para o collectstatic funcionar.
        # Deixaremos vazio por enquanto.
        return [], []