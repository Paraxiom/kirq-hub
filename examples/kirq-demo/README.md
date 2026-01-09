# Kirq-Demo 🛡️🔒

Une démonstration des possibilités du banc d'essai en télécommunication quantique : [Kirq](https://kirq.numana.tech/en/).

## Description du Projet 📄

Cette application illustre l'utilisation de technologies résilientes aux attaques quantiques, dites _'Quantum Safe'_. Deux méthodes sont disponibles: 

- **🔑 QKD (Quantum Key Distribution)** : Installé sur le banc d'essai accessible à distance par le VPN[^1].
- **🛡️ PQC (Post-Quantum Cryptography)** : Utilisation des derniers algorithmes sélectionnés par le [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography), notamment [ML-KEM](https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html).

[^1]: Pour accéder au VPN et au banc d'essai, l'abonnement en tant qu'utilisateur est obligatoire. Une fois l'inscription validée, nous vous fournirons vos identifiants d'accès.

Les utilisateurs peuvent se connecter à leur email (Alice) et envoyer des messages cryptés à une autre adresse email (Bob), qui peut ensuite déchiffrer le message à son tour. Les emails incluent des métadonnées précieuses notamment pour le décryptage.

## Installation et Lancement ⚙️

### Prérequis

- **💻 Système d'exploitation** : Compatible avec les systèmes pouvant exécuter Docker.
- **🐳 Docker** : Assurez-vous d'avoir Docker installé sur votre machine. Si nécessaire, consultez [docker.com](https://www.docker.com/) pour des instructions d'installation.

### Instructions d'installation

1. **Cloner le dépôt** :
   ```bash
   git clone https://github.com/Numana-official/kirq-demo.git
   cd kirq-demo
   ```

2. **Construire l'image Docker** :
   À partir du répertoire racine, veuillez exécuter :
   ```bash
   docker build -f app/Dockerfile -t kirq-demo .
   ```

3. **Lancer le conteneur** :
   ```bash
   docker run --rm -p 8501:8501 kirq-demo
   ```

### Accès à l'application

- Ouvrez votre navigateur web et accédez à [http://localhost:8501](http://localhost:8501) pour utiliser l'application Streamlit déployée.

![image](https://github.com/user-attachments/assets/2a5992f0-f574-4719-9df9-fe4bcf90f318)


## Instructions d'utilisation ✉️

Pour utiliser l'application et se connecter à votre email, créez un mot de passe d'application. Cette fonctionnalité est compatible avec Gmail, mais incompatible avec Outlook. Le test avec d'autres services email n'a pas été réalisé.

Si vous recevez un email chiffré sans possibilité de connexion, utilisez l'option de décryptage manuel en copiant le message chiffré et les métadonnées.

## Contributions 🚫

Ce dépôt est privé et n'accepte pas de contributions externes.

## Protection sous Copyright ©

Le code source de cette application est protégé par les lois sur le droit d'auteur. Cela signifie que tous les droits relatifs au code sont réservés et appartiennent légalement à l'entité responsable. Toute reproduction, distribution, modification, affichage public, diffusion publique, réutilisation, ou toute autre forme d'utilisation du code sans autorisation explicite est strictement interdite et peut entraîner des sanctions légales.

## Informations de contact 📞

Pour toute question ou support, veuillez contacter l'architecte de systèmes de Numana :
- **Emmanuel Calvet** - [ecalvet@numana.tech]
