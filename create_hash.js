// Archivo: create_hash.js
const bcrypt = require('bcryptjs');

// --- MODIFIQUE ESTA LÍNEA ---
const passwordToHash = 'Rocket0001'; 

// --- NO MODIFIQUE DEBAJO DE ESTA LÍNEA ---
const saltRounds = 10;

if (!passwordToHash || passwordToHash === 'password123') {
  console.error("\nERROR: Por favor, edite el archivo 'create_hash.js' y cambie la variable 'passwordToHash' a su contraseña deseada.\n");
  process.exit(1);
}

console.log(`Generando hash para la contraseña: "${passwordToHash}"`);

bcrypt.hash(passwordToHash, saltRounds, (err, hash) => {
  if (err) {
    console.error("Error al generar el hash:", err);
    return;
  }
  console.log("\n--- HASH GENERADO CON ÉXITO ---");
  console.log("Copie y pegue la siguiente línea completa en su comando SQL:\n");
  console.log(hash);
  console.log("\n---------------------------------");
});