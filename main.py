# main.py (MODO OPERATIVO COMPLETO)
import functions_framework
import openai
import os
from flask import jsonify

openai.api_key = os.environ.get("OPENAI_API_KEY")

@functions_framework.http
def summarize(request):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    }
    if request.method == 'OPTIONS':
        return ('', 204, headers)

    print("AURA_BRAIN [OPERATIONAL MODE]: Función invocada.")
    request_json = request.get_json(silent=True)
    if not request_json or 'text' not in request_json:
        print("AURA_BRAIN [ERROR]: Payload inválido.")
        return (jsonify({"error": "Payload inválido. Se requiere 'text'."}), 400, headers)

    chat_text = request_json['text']

    try:
        print("AURA_BRAIN [INFO]: Contactando a OpenAI...")
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente de soporte que resume el problema principal de un cliente en una frase concisa y directa."},
                {"role": "user", "content": chat_text}
            ],
            temperature=0.3,
            max_tokens=100
        )
        summary = response.choices[0].message.content.strip()
        print("AURA_BRAIN [SUCCESS]: Resumen recibido de OpenAI.")
        return (jsonify({"summary": summary}), 200, headers)

    except Exception as e:
        # Este es el log que ahora SÍ veremos si algo falla
        print(f"AURA_BRAIN [CRITICAL FAILURE]: Error al llamar a OpenAI: {e}")
        return (jsonify({"error": "El motor de IA no pudo procesar la solicitud."}), 500, headers)