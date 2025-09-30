# Use uma imagem base oficial do Python
FROM python:3.11-slim

# Defina variáveis de ambiente para o Python
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Crie e defina o diretório de trabalho
WORKDIR /app

# Copie o arquivo de dependências e instale-as
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie todo o código do projeto para o diretório de trabalho
COPY . .

# Execute o collectstatic para reunir os arquivos estáticos no STATIC_ROOT
RUN python manage.py collectstatic --no-input

# Exponha a porta que o Gunicorn irá usar
EXPOSE 8080

# Comando para iniciar o servidor Gunicorn
# O Cloud Run define a variável de ambiente PORT, que usamos aqui.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 core.wsgi:application