import express from 'express';
import { clerkMiddleware, getAuth, requireAuth } from '@clerk/express';
import { createClerkClient } from '@clerk/backend';
import dotenv from 'dotenv';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Setup Clerk client
const clerkClient = createClerkClient({
  secretKey: process.env.CLERK_SECRET_KEY,
  publishableKey: process.env.CLERK_PUBLISHABLE_KEY
});

// Directory setup for serving HTML
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(clerkMiddleware());

// Role-based middleware
const authorize = (roles = []) => {
  return async (req, res, next) => {
    try {
      const user = await clerkClient.users.getUser(req.auth.userId);
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

// org based middle ware 
const authorizeOrgAdmin = () => {
  return async (req, res, next) => {
    try {
      console.log(req.auth());
      const { userId, orgId } = req.auth();
   console.log('User ID:', userId, 'Organization ID:', orgId);
      if (!orgId) {
        return res.status(403).json({ message: 'Access denied: no organization context' });
      }

      // Get org memberships
     
    const memberships = await clerkClient.organizations.getOrganizationMembershipList({ organizationId: orgId });
    console.log('memberships:', memberships);
    const currentMembership = memberships.data.find(m => m.publicUserData.userId === userId);
      console.log('Current Membership:', currentMembership);

     if (
  !currentMembership ||
  (currentMembership.role !== 'admin' && currentMembership.role !== 'org:admin')
) {
  return res.status(403).json({ message: 'Access denied: organization admin only' });
}


      next();
    } catch (err) {
      console.error("Auth error:", err);
      return res.status(500).json({ message: 'Failed to verify organization admin role' });
    }
  };
};

// Routes
app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/new-user', (req, res) => {
  res.json({
    message: 'Welcome to the new user page! Please sign up via Clerk to access secure routes.'
  });
});

app.get('/dashboard', requireAuth(),authorizeOrgAdmin(), async (req, res) => {
  try {
    console.log('Dashboard accessed');
    const { userId, orgId } = req.auth();

    if (!orgId) {
      return res.status(403).json({ message: "User is not in an organization" });
    }

    const user = await clerkClient.users.getUser(userId);
    const org = await clerkClient.organizations.getOrganization({ organizationId: orgId });
    const memberships = await clerkClient.organizations.getOrganizationMembershipList({ organizationId: orgId });
    console.log('memberships:', memberships);
    const currentMembership = memberships.data.find(m => m.publicUserData.userId === userId);

    return res.json({
      user: {
        id: user.id,
        email: user.emailAddresses[0]?.emailAddress,
        name: `${user.firstName} ${user.lastName}`
      },
      organization: {
        id: org.id,
        name: org.name,
        role: currentMembership?.role
      }
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/secure', requireAuth(), authorizeOrgAdmin(), (req, res) => {
  res.json({ message: 'walcome Admin!!This is a secure route accessible only to admins.' });
});


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
