const nodemailer = require('nodemailer');

async function sendTestMail() {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'alpmangulay0@gmail.com',       
      pass: 'vtuwrldrebuuijrx'                
    }
  });

  let info = await transporter.sendMail({
    from: '"Vera Otel" <alpmangulay0@gmail.com>',   
    to: 'timuralpman1782@gmail.com',                    
    subject: 'Test Maili',
    text: 'Merhaba, bu bir test mailidir!',
  });

  console.log('Mail gönderildi:', info.messageId);
}

// Fonksiyonu hemen çalıştırmak için:
sendTestMail().catch(console.error);
