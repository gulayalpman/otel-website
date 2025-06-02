require('dotenv').config(); // .env dosyasını okuyacak

const bcrypt = require('bcrypt');
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // .env üzerinden Stripe anahtarı alınır

const app = express();
const port = 3000;

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Oda fiyatları (kuruş cinsinden)
const roomPrices = {
  standart: 80000,
  deluxe: 120000,
  suit: 180000
};

async function startServer() {
  try {
    await client.connect();
    console.log("MongoDB'ye başarıyla bağlanıldı!");

    const database = client.db('otelDB');
    const store = new MongoDBStore({
      uri: uri,
      collection: 'sessions'
    });

    store.on('error', function(error) {
      console.error('Session Store Error:', error);
    });


    app.use(express.json());

    app.use(session({
      secret: 'bu-cok-gizli-bir-secret',
      resave: false,
      saveUninitialized: false,
      store: store,
      cookie: {
        maxAge: 1000 * 60 * 60 * 24
      }
    }));

    app.use(express.static('public'));

    function isAuthenticated(req, res, next) {
      if (req.session.userId) {
        next();
      } else {
        res.status(401).send('Yetkisiz erişim');
      }
    }

    function isAdmin(req, res, next) {
      if (req.session.role === 'admin') {
        next();
      } else {
        res.status(403).json({ message: 'Erişim reddedildi. Admin olmanız gerekiyor.' });
      }
    }

    app.get('/', (req, res) => {
      res.sendFile(__dirname + '/public/index.html');
    });

    app.get('/dashboard', isAuthenticated, (req, res) => {
      if (req.session.role === 'admin') {
        res.sendFile(__dirname + '/public/dashboard-admin.html');
      } else if (req.session.role === 'misafir') {
        res.sendFile(__dirname + '/public/dashboard-misafir.html');
      } else {
        res.redirect('/');
      }
    });

    app.post('/register', async (req, res) => {
      try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
          return res.status(400).json({ message: "Tüm alanlar zorunludur." });
        }

        const usersCollection = database.collection('users');
        const existingUser = await usersCollection.findOne({ email: email });

        if (existingUser) {
          return res.status(409).json({ message: "Bu email zaten kayıtlı." });
        }

        const verificationCode = generateVerificationCode(6);

        const result = await usersCollection.insertOne({
          username,
          email,
          password: await bcrypt.hash(password, 10),
          role: 'misafir',
          verificationCode,
          verified: false
        });

        const mailOptions = {
          from: '"Vera Otel" <alpmangulay0@gmail.com>',
          to: email,
          subject: 'Hesap Doğrulama Kodu',
          text: `Merhaba ${username},\n\nHesabınızı doğrulamak için kodunuz: ${verificationCode}\n\nTeşekkürler!`
        };

        try {
        await transporter.sendMail(mailOptions);
      } catch (mailError) {
        console.error("Mail gönderilemedi:", mailError);
      }

        res.status(201).json({
          message: "Kayıt başarılı! Doğrulama kodu mail adresinize gönderildi.",
          userId: result.insertedId,
          redirectUrl: "/verify.html"
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Sunucu hatası." });
      }
    });

    app.post('/verify-email', async (req, res) => {
      try {
        const { email, verificationCode } = req.body;
        const usersCollection = database.collection('users');

        const user = await usersCollection.findOne({ email: email });
        if (!user) {
          return res.status(404).json({ message: "Kullanıcı bulunamadı." });
        }

        if (user.verified) {
          return res.status(400).json({ message: "Hesap zaten doğrulanmış." });
        }

        if (user.verificationCode !== verificationCode) {
          return res.status(400).json({ message: "Doğrulama kodu yanlış." });
        }

        await usersCollection.updateOne({ email: email }, { $set: { verified: true } });

        res.status(200).json({ message: "E-posta başarıyla doğrulandı." });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Sunucu hatası." });
      }
    });

    app.post('/admin/update-role', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const { userId, newRole } = req.body;
        if (!ObjectId.isValid(userId)) {
          return res.status(400).json({ message: 'Geçersiz kullanıcı ID’si.' });
        }
        if (!newRole) {
          return res.status(400).json({ message: 'Yeni rol belirtilmeli.' });
        }

        const usersCollection = database.collection('users');
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { role: newRole } }
        );

        if (result.modifiedCount === 0) {
          return res.status(404).json({ message: 'Kullanıcı bulunamadı veya rol değişmedi.' });
        }

        res.json({ message: 'Rol başarıyla güncellendi.' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    app.post('/login', async (req, res) => {
      console.log('POST /login isteği geldi:', req.body);
      try {
        const { email, password } = req.body;
        if (!email || !password) {
          return res.status(400).json({ message: "E-posta ve şifre zorunludur." });
        }

        const usersCollection = database.collection('users');
        const user = await usersCollection.findOne({ email: email });

        if (!user) {
          return res.status(401).json({ message: "Kullanıcı bulunamadı." });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res.status(401).json({ message: "Şifre yanlış." });
        }

        if (!user.verified) {
          return res.status(403).json({ message: "Lütfen önce e-posta adresinizi doğrulayın." });
        }

        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.role = user.role;

        res.status(200).json({ message: "Giriş başarılı!", userId: user._id, role: user.role });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Sunucu hatası." });
      }
    });

    app.get('/logout', (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          console.error("Oturum sonlandırılırken hata:", err);
          return res.status(500).json({ message: "Çıkış yapılamadı." });
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
      });
    });

    // Rezervasyon ekleme ve ödeme intent oluşturma
    app.post('/reservations', async (req, res) => {
      try {
        const { name, email, room, checkin, checkout } = req.body;

        if (!name || !email || !room || !checkin || !checkout) {
          return res.status(400).json({ message: 'Tüm alanlar zorunludur.' });
        }

        const reservationsCollection = database.collection('reservations');

        // Tarihleri Date objesine çevir (önemli)
        const checkinDate = new Date(checkin);
        const checkoutDate = new Date(checkout);

        // Gece sayısı hesapla
        const msPerDay = 1000 * 60 * 60 * 24;
        const nights = Math.ceil((checkoutDate - checkinDate) / msPerDay);

        // Oda fiyatı al
        const pricePerNight = roomPrices[room.toLowerCase()] || 10000;

        // Toplam tutar (kuruş cinsinden)
        const amount = pricePerNight * nights;

        // Rezervasyonu kaydet
        const result = await reservationsCollection.insertOne({
          name,
          email,
          room,
          checkin: checkinDate,
          checkout: checkoutDate,
          amount,
          createdAt: new Date()
        });

        // Stripe PaymentIntent oluştur
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: 'try',
          payment_method_types: ['card'],
          metadata: {
            reservationId: result.insertedId.toString(),
            email: email,
            name: name
          }
        });

        res.status(201).json({
          message: 'Rezervasyon kaydedildi!',
          reservationId: result.insertedId,
          clientSecret: paymentIntent.client_secret,
          amount: amount
        });

      } catch (error) {
        console.error("Rezervasyon kaydederken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası' });
      }
    });

    // Rezervasyonları listeleme - giriş yapmış kullanıcıya göre
    app.get('/reservations', async (req, res) => {
      try {
        let emailQuery = req.query.email;

        if (req.session && req.session.userId) {
          const usersCollection = database.collection('users');
          const user = await usersCollection.findOne({ _id: new ObjectId(req.session.userId) });
          if (user) {
            emailQuery = user.email;
          }
        }

        if (!emailQuery) {
          return res.status(400).json({ message: 'Email sorgu parametresi gereklidir.' });
        }

        const reservationsCollection = database.collection('reservations');
        const now = new Date();

        const activeReservations = await reservationsCollection.find({
          email: emailQuery,
          checkout: { $gte: now }
        }).toArray();

        const pastReservations = await reservationsCollection.find({
          email: emailQuery,
          checkout: { $lt: now }
        }).toArray();

        res.json({ active: activeReservations, past: pastReservations });
      } catch (error) {
        console.error('Rezervasyonlar sorgulanırken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası' });
      }
    });

    // Ödeme başarılı olduğunda çağrılacak endpoint
    app.post('/payment-success', async (req, res) => {
      try {
        const { reservationId, email, name, amount } = req.body;
        console.log("📩 Gelen ödeme bilgileri:", { reservationId, email, name, amount });
        if (!reservationId || !email || !name || !amount) {
          return res.status(400).json({ message: 'Eksik bilgi var.' });
        }

        // Ödeme onay mailini gönder
        const mailOptions = {
          from: '"Vera Otel" <alpmangulay0@gmail.com>',
          to: email,
          subject: 'Ödemeniz Başarıyla Alındı',
          text: `Merhaba ${name},\n\nÖdemeniz başarıyla alınmıştır. Toplam tutar: ${(amount / 100).toFixed(2)} TL.\nRezervasyonunuz onaylandı. Teşekkür ederiz!`
        };

        try {
        await transporter.sendMail(mailOptions);
      } catch (mailError) {
        console.error("Mail gönderilemedi:", mailError);
      }

        const reservationsCollection = database.collection('reservations');
        await reservationsCollection.updateOne(
          { _id: new ObjectId(reservationId) },
          { $set: { paymentStatus: 'paid' } }
        );
        res.status(200).json({ message: 'Onay maili gönderildi ve rezervasyon güncellendi.' });
      } catch (error) {
        console.error('Ödeme onay maili gönderilirken hata:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Kullanıcıları listeleme
    app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const usersCollection = database.collection('users');
        const users = await usersCollection.find({}).toArray();
        res.json(users);
      } catch (error) {
        console.error("Kullanıcılar alınamadı:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Kullanıcı silme
    app.delete('/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const userId = req.params.id;
        if (!ObjectId.isValid(userId)) {
          return res.status(400).json({ message: 'Geçersiz kullanıcı ID’si.' });
        }

        const usersCollection = database.collection('users');
        const result = await usersCollection.deleteOne({ _id: new ObjectId(userId) });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }

        res.json({ message: 'Kullanıcı başarıyla silindi.' });
      } catch (error) {
        console.error("Kullanıcı silinirken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Odaları listeleme
    app.get('/admin/rooms', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const roomsCollection = database.collection('rooms');
        const rooms = await roomsCollection.find({}).toArray();
        res.json(rooms);
      } catch (error) {
        console.error("Odalar alınamadı:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Oda ekleme
    app.post('/admin/rooms', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const { name, type, price, status } = req.body;
        const roomsCollection = database.collection('rooms');
        const result = await roomsCollection.insertOne({ name, type, price, status });
        res.status(201).json({ message: 'Oda eklendi!', roomId: result.insertedId });
      } catch (error) {
        console.error("Oda eklenirken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Oda güncelleme
    app.put('/admin/rooms/:id', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const roomId = req.params.id;
        const { name, type, price, status } = req.body;
        const roomsCollection = database.collection('rooms');
        const result = await roomsCollection.updateOne(
          { _id: new ObjectId(roomId) },
          { $set: { name, type, price, status } }
        );
        res.json({ message: 'Oda güncellendi.' });
      } catch (error) {
        console.error("Oda güncellenirken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Oda silme
    app.delete('/admin/rooms/:id', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const roomId = req.params.id;
        const roomsCollection = database.collection('rooms');
        const result = await roomsCollection.deleteOne({ _id: new ObjectId(roomId) });
        res.json({ message: 'Oda silindi.' });
      } catch (error) {
        console.error("Oda silinirken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    
// ✅ Admin tarafından manuel olarak ödenmiş olarak işaretleme
app.post('/admin/mark-paid/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const reservationId = req.params.id;
    const reservationsCollection = database.collection('reservations');
    const result = await reservationsCollection.updateOne(
      { _id: new ObjectId(reservationId) },
      { $set: { paymentStatus: 'paid' } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Rezervasyon bulunamadı veya zaten ödenmiş olabilir.' });
    }

    res.status(200).json({ message: 'Rezervasyon manuel olarak ödenmiş olarak işaretlendi.' });
  } catch (error) {
    console.error("Manuel ödeme işareti hatası:", error);
    res.status(500).json({ message: 'Sunucu hatası.' });
  }
});


// ✅ Tüm rezervasyonları listeleme (admin için)
    app.get('/admin/reservations', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const reservationsCollection = database.collection('reservations');
        const reservations = await reservationsCollection.find({}).toArray();
        res.json(reservations);
      } catch (error) {
        console.error("Tüm rezervasyonlar alınamadı:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Ayarları kaydetme
    app.post('/admin/settings', isAuthenticated, isAdmin, async (req, res) => {
      try {
        const { contactEmail, supportPhone, mailSubject } = req.body;
        const settingsCollection = database.collection('settings');
        await settingsCollection.updateOne(
          { _id: 'site-settings' },
          { $set: { contactEmail, supportPhone, mailSubject } },
          { upsert: true }
        );
        res.json({ message: 'Ayarlar güncellendi.' });
      } catch (error) {
        console.error("Ayarlar güncellenemedi:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    // ✅ Ayarları getirme
    app.get('/admin/settings', async (req, res) => {
      try {
        const settingsCollection = database.collection('settings');
        const settings = await settingsCollection.findOne({ _id: 'site-settings' });
        res.json(settings || {});
      } catch (error) {
        console.error("Ayarlar alınamadı:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });

    
    // ✅ İletişim mesajlarını kaydetme ve mail gönderme
    app.post('/contact', async (req, res) => {
      try {
        const { name, email, message } = req.body;
        if (!name || !email || !message) {
          return res.status(400).json({ message: 'Tüm alanlar zorunludur.' });
        }

        const contactsCollection = database.collection('contacts');

        // Veritabanına kayıt
        await contactsCollection.insertOne({
          name,
          email,
          message,
          createdAt: new Date()
        });

        // E-posta gönderimi
        const mailOptions = {
          from: '"Vera Otel İletişim" <alpmangulay0@gmail.com>',
          to: 'alpmangulay0@gmail.com',
          subject: 'Yeni İletişim Formu Mesajı',
          text: `Yeni mesaj alındı:

Ad: ${name}
E-posta: ${email}

Mesaj:
${message}`
        };

        try {
        await transporter.sendMail(mailOptions);
      } catch (mailError) {
        console.error("Mail gönderilemedi:", mailError);
      }

        res.status(200).json({ message: 'Mesajınız başarıyla gönderildi!' });
      } catch (error) {
        console.error("İletişim mesajı gönderilirken hata:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
      }
    });


    app.listen(port, () => {
      console.log(`Sunucu http://localhost:${port} adresinde çalışıyor.`);
    });

    // ✅ Manuel rezervasyon oluşturma endpointi
app.post('/admin/manual-reservation', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { name, email, room, checkin, checkout } = req.body;

    if (!name || !email || !room || !checkin || !checkout) {
      return res.status(400).json({ message: 'Tüm alanlar zorunludur.' });
    }

    const checkinDate = new Date(checkin);
    const checkoutDate = new Date(checkout);
    const nights = Math.ceil((checkoutDate - checkinDate) / (1000 * 60 * 60 * 24));
    const pricePerNight = roomPrices[room.toLowerCase()] || 10000;
    const amount = pricePerNight * nights;

    const reservationsCollection = database.collection('reservations');
    const result = await reservationsCollection.insertOne({
      name,
      email,
      room,
      checkin: checkinDate,
      checkout: checkoutDate,
      amount,
      paymentStatus: 'paid',
      createdAt: new Date()
    });

    const mailOptions = {
      from: '"Vera Otel" <alpmangulay0@gmail.com>',
      to: email,
      subject: 'Rezervasyon Onayı',
      text: `Merhaba ${name},\n\nRezervasyonunuz başarıyla oluşturulmuştur. Toplam tutar: ${(amount / 100).toFixed(2)} TL.\nTeşekkür ederiz!`
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (mailError) {
      console.error("Mail gönderilemedi:", mailError);
    }

    res.status(201).json({ message: 'Manuel rezervasyon başarıyla oluşturuldu.' });
  } catch (error) {
    console.error("Manuel rezervasyon hatası:", error);
    res.status(500).json({ message: 'Sunucu hatası.' });
  }
});

  } catch (error) {
    console.error(error);
  }
}

startServer();
