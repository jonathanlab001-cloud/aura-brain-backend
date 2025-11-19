# Usar una imagen base ligera de Node.js 20 (Alpine Linux)
FROM node:20-alpine

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /usr/src/app

# Copiar los archivos de definición de dependencias
COPY package*.json ./

# Instalar solo las dependencias de producción (más rápido y ligero)
RUN npm ci --only=production

# Copiar el resto del código fuente de la aplicación
COPY . .

# Cloud Run inyecta la variable PORT, pero exponemos 8080 por convención
EXPOSE 8080
ENV PORT 8080

# Comando para iniciar la aplicación
CMD ["npm", "start"]
