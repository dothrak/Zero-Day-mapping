import ollama

PROMPT_TEMPLATE = """
Tu es un expert en cybersécurité et logiciels. 
Donne-moi les configurations affectées par la CVE suivante : CVE-2025-8643.
"""

# Appel au modèle Mistral
response = ollama.chat(
    model="mistral",
    messages=[{"role": "user", "content": PROMPT_TEMPLATE}]
)

# Affichage de la réponse brute
print(response)
