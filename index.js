const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session'); // 1. added this
const KnexSessionStore = require('connect-session-knex')(session); // 1) then added this

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

// 3. added this
const sessionConfig = {
  name: 'cookieMonster',
  secret: 'C is for cookie.',
  cookie: {
    maxAge: 1000 * 60 * 15, // in ms - 1000ms = 60sec; 60sec=1min * 15min 
    secure: false, // used over https only
  },
  httpOnly: true, // cannot access the cookie from js document.cookie
  resave: false, // save even if no changes in data
  saveUninitialized: false, // GDPR laws against setting cookies automatically
   // 2) then added this
  store: new KnexSessionStore({
    knex: db,
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 60, // in ms - clears only the expired sessions
  }),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); // 2. added this

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  // generate hash from user's password
  const hash = bcrypt.hashSync(user.password, 12);
  // override user.password with hash
  user.password = hash

  Users.add(user)
    .then(saved => {
      req.session.user = saved; // so user doesn't have to login after register?
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check that passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user; // 4. added this
        res.status(200).json({ message: `Welcome ${user.username}!, have a cookie.` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// 5. simplified this
function restricted (req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: 'You shall not pass!' });
  }
}

// // protect this route, only authenticated users should see it
// function restricted (req, res, next) {
//   const { username, password } = req.headers

//   if (username && password) {
//     Users.findBy({ username })
//       .first()
//       .then(user => {
//         if (user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: 'Invalid Credentials'});
//         }
//       })
//       .catch(error => {
//         res.status(500).json(error);
//       })
//   } else {
//     res.status(400).json({ message: 'No Credentials Provided' });
//   }
// }

server.post('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
        res.json(users);
    })
    .catch(err => res.send(err));
});

// server.get('/api/users', restricted, async (req, res) => {
//   try {
//     const users = await users.find()
//     res.json(users)
//   } catch(error) {
//     res.send(error)
//   }
// })

server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send('Error logging out.')
      } else {
        res.send('Goodbye')
      }
    })
  } else {
    res.end();
  }
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
