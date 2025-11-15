const fetch = require('node-fetch');

async function testAuraBackend() {
  const url = 'https://southamerica-west1-aura-operations.cloudfunctions.net/auraBackend';

  const prompt = "Resume brevemente la importancia de la inteligencia artificial en la atención al cliente.";

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });

    if (!response.ok) {
      console.error(`Error en la respuesta: ${response.status} ${response.statusText}`);
      const errorText = await response.text();
      console.error(errorText);
      return;
    }

    const data = await response.json();
    console.log('Respuesta de Aura Backend:', data.result);
  } catch (error) {
    console.error('Error al llamar a la función:', error);
  }
}

testAuraBackend();