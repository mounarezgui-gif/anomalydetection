# ---- Étape 1 : build de l'app React ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

# ---- Étape 2 : serveur de production ----
# On réutilise le node_modules déjà installé en étape 1 (contient express)
# pour éviter un second "npm install" qui provoque des conflits de versions.
FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./
COPY server.js ./

EXPOSE 3000
CMD ["node", "server.js"]