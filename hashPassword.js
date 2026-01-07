// hashPassword.js
const bcrypt = require('bcryptjs');

const password = 'admin123'; // replace with your desired password

bcrypt.hash(password, 10)
  .then(hash => {
    console.log('Hashed password:', hash);
  })
  .catch(err => console.error(err));
