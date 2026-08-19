# Lancement du projet

## Etape 1 : construction des images docker

```docker build -f Dockerfile.kme -t qkd-kme .```  
```docker build -f Dockerfile.sae -t qkd-sae .```

## Etape 2 : création du réseau docker

```docker network create qkd-net```  

## Etape 3 : lancement du serveur KME

```docker run -d --name kme --network qkd-net -p 8000:8000 qkd-kme```  

Essai :
```curl http://localhost:8000/api/v1/keys/SAE_B/status```

## Etape 4 : Execution de la SAE A

Crée le conteneur et le supprime directement apres execution  
<code>docker run --rm --network qkd-net \
  -e KME_URL=http://kme:8000 \
  -e SAE_ID=SAE_A \
  -e PEER_SAE_ID=SAE_B \
  -e SAE_ROLE=master \
  qkd-sae</code>  

IMPORTANT : récupérer la key_ID affiché pour l'étape 5

## Etape 5 : Execution de la SAE B

Crée le conteneur et le supprime directement apres execution  
<code>docker run --rm --network qkd-net \
  -e KME_URL=http://kme:8000 \
  -e SAE_ID=SAE_B \
  -e PEER_SAE_ID=SAE_A \
  -e SAE_ROLE=slave \
  -e KEY_ID=<key_ID_obtenu_à_l'étape_4> \
  qkd-sae</code>

## Fin d'utilisation

```docker stop kme && docker rm kme```  
```docker network rm qkd-net```