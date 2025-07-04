
import express from 'express';
import { Clerk,ClerkExpressRequireAuth,ClerkExpressWithAuth ,clerkClient} from '@clerk/clerk-sdk-node';
import dotenv from 'dotenv';
dotenv.config();
const app = express();
const port = process.env.PORT;
import cors from 'cors';
const clerk = new Clerk({ apiKey: process.env.CLERK_SECRET_KEY });

app.use(cors());
// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static HTML
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Middleware: Authenticate using Clerk token
import { verifyToken } from '@clerk/backend';

const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing token' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = await verifyToken(token, {
      secretKey: process.env.CLERK_SECRET_KEY
    });

    req.auth = {
      sessionId: payload.sid,
      userId: payload.sub,
    };

    next();
  } catch (err) {
    console.error("Token verification error:", err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};
// Middleware: Role-based access
const authorize = (roles = []) => {
  return async (req, res, next) => {
    try {
      const user = await clerkClient.users.getUser(req.userId);
      const role = user.publicMetadata.role;

      if (!roles.includes(role)) {
        return res.status(403).json({ message: 'Access denied: role required' });
      }

      next();
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch user info' });
    }
  };
};

app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname,"public" ,'index.html'));
});
app.get('/login', (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', authenticate,async (req, res) =>{
  console.log('Dashboard accessed');
  console.log(req.auth);
   const {userId} = req.auth;
   if(!userId) {
     return res.status(401).json({ error: 'Unauthorized' });
   }
   const users = await clerkClient.users.getUser(userId);
   console.log(users);
   res.json(users);
});

app.get('/signup', (req, res) => {
   res.sendFile(path.join(__dirname,"public" ,'signup.html'));
});
app.get('/new-user', (req, res) => {
  res.json({
    message: 'Welcome to the new user page! Please sign up via Clerk to access secure routes.'})
    
});



app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`)});