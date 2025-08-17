const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3000;
const admin = require("firebase-admin");

const stripe = require("stripe")(process.env.PAYMENT_GATEWAY_KEY);
// Middleware
app.use(cors());
app.use(express.json());

// firebase admin 
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decodedKey)

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// mongoDB
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


async function run() {
  try {
    // Database collections
    const db = client.db("eduSyncDB");
    const usersCollection = db.collection("users");
    const notesCollection = db.collection("notes");
    const sessionsCollection = db.collection("sessions");
    const materialsCollection = db.collection("materials");
    const announcementsCollection = db.collection("announcements");
    const bookedSessionsCollection = db.collection("bookedSessions");
    const paymentsCollection = db.collection("payments");
    const reviewsCollection = db.collection("reviews");


    // custom middlewares
    const verifyFBToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' })
      }
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).send({ message: 'unauthorized access' })
      }

      // verify the token
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
      }
      catch (error) {
        return res.status(403).send({ message: 'forbidden access' })
      }
    }

    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email }
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== 'admin') {
        return res.status(403).send({ message: 'forbidden access' })
      }
      next();
    }

    const verifyTutor = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email }
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== 'tutor') {
        return res.status(403).send({ message: 'forbidden access' })
      }
      next();
    }

    // **User**
    // GET: Get user role by email
    app.get('/users/:email/role', async (req, res) => {
      try {
        const { email } = req.params;
        if (!email) {
          return res.status(400).send({ message: 'Email is required' });
        }
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ role: user.role || 'student' });
      } catch (error) {
        console.error('Error getting user role:', error);
        res.status(500).send({ message: 'Failed to get role' });
      }
    });

    // GET: Get user by _id (admin only)
    app.get('/users/:id', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!id) {
          return res.status(400).send({ message: 'User id is required' });
        }
        let user;
        try {
          user = await usersCollection.findOne({ _id: new ObjectId(id) });
        } catch (e) {
          return res.status(400).send({ message: 'Invalid user id' });
        }
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send(user);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user by id' });
      }
    });


    // users api
    // verifyFBToken, verifyAdmin,
    app.get('/users', verifyFBToken, async (req, res) => {
      try {
        const { search, role, page: pageQuery, limit: limitQuery } = req.query;
        const requesterEmail = req.decoded.email;
        const requester = await usersCollection.findOne({ email: requesterEmail });

        // If a specific user is being searched for by email, and it's the requester's email
        if (search && search === requesterEmail && !role && !pageQuery && !limitQuery) {
          const user = await usersCollection.findOne({ email: search });
          return res.send({ users: user ? [user] : [] });
        }

        // Admin-only access for full user list
        if (!requester || requester.role !== 'admin') {
          return res.status(403).send({ message: 'forbidden access' });
        }

        const page = parseInt(pageQuery) || 1;
        const limit = parseInt(limitQuery) || 5;
        const skip = (page - 1) * limit;
        let query = {};
        if (search) {
          query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { displayName: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
          ];
        }
        if (role && role !== 'all') {
          query.role = role;
        }
        const totalItems = await usersCollection.countDocuments(query);
        const totalPages = Math.ceil(totalItems / limit);
        const users = await usersCollection.find(query).skip(skip).limit(limit).toArray();
        res.send({
          users,
          totalPages,
          totalItems,
          currentPage: page,
          itemsPerPage: limit
        });
      } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send({ message: 'Failed to fetch users' });
      }
    });

    // Add or update the POST /users endpoint to enforce default role 'student'
    app.post('/users', async (req, res) => {
      try {
        const userData = req.body;
        if (!userData.email) {
          return res.status(400).send({ message: 'Email is required' });
        }
        // Set default role to 'student' if not provided
        if (!userData.role) {
          userData.role = 'student';
        }
        // Prepare user document with all fields
        const userDocument = {
          email: userData.email,
          name: userData.name || userData.displayName || '',
          photoURL: userData.photoURL || '',
          role: userData.role,
          created_at: userData.created_at || new Date().toISOString(),
          last_log_in: userData.last_log_in || new Date().toISOString(),
        };
        // Upsert user (update if exists, insert if not)
        const result = await usersCollection.updateOne(
          { email: userData.email },
          { $setOnInsert: userDocument },
          { upsert: true }
        );
        res.send({ success: true, result });
      } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).send({ message: 'Failed to create user' });
      }
    });

    // PUT: Update user by _id (for profile editing)
    app.put('/users/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const requesterEmail = req.decoded.email;

        // Find the user to be updated
        let userToUpdate;
        try {
          userToUpdate = await usersCollection.findOne({ _id: new ObjectId(id) });
        } catch (e) {
          return res.status(400).send({ message: 'Invalid user id' });
        }

        if (!userToUpdate) {
          return res.status(404).send({ message: 'User not found' });
        }

        // Check if the requester is the user being updated
        if (userToUpdate.email !== requesterEmail) {
          // If not, check if the requester is an admin
          const requester = await usersCollection.findOne({ email: requesterEmail });
          if (!requester || requester.role !== 'admin') {
            return res.status(403).send({ message: 'You are not authorized to update this profile.' });
          }
        }

        // Only allow updating certain fields
        const allowedFields = ['photoURL', 'phoneNumber', 'address', 'website', 'linkedin', 'github', 'facebook', 'bio', 'name', 'displayName'];
        const setDoc = {};
        for (const key of allowedFields) {
          if (updateData[key] !== undefined) setDoc[key] = updateData[key];
        }
        if (Object.keys(setDoc).length === 0) {
          return res.status(400).send({ message: 'No valid fields to update' });
        }
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: setDoc }
        );
        if (result.matchedCount === 0) {
          // This case should ideally not be reached due to the check above, but as a safeguard:
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update user' });
      }
    });

    // PATCH: Update user role
    app.patch('/users/:email/role', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { email } = req.params;
        const { role } = req.body;

        if (!email || !role) {
          return res.status(400).send({ message: 'Email and role are required' });
        }

        if (!['admin', 'tutor', 'student'].includes(role)) {
          return res.status(400).send({ message: 'Invalid role. Must be admin, tutor, or student' });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: { role } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
        }

        res.send({ success: true, message: 'User role updated successfully' });
      } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).send({ message: 'Failed to update user role' });
      }
    });

    // **Tutors**

    // Public: Get all tutors (users with role 'tutor')
    app.get('/tutors', async (req, res) => {
      try {
        // Exclude the email field from the result
        const tutors = await usersCollection.find(
          { role: 'tutor' },
          { projection: { email: 0 } }
        ).toArray();
        res.send(tutors);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch tutors' });
      }
    });
    // **Students**

    // Public: Get all students (users with role 'student') with pagination
    app.get('/students', verifyFBToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalItems = await usersCollection.countDocuments({ role: 'student' });
        const totalPages = Math.ceil(totalItems / limit);

        // Get paginated students
        const students = await usersCollection
          .find({ role: 'student' })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          students,
          totalPages,
          totalItems,
          currentPage: page,
          itemsPerPage: limit
        });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch students' });
      }
    });

    // **Notes**

    // GET: Get notes api
    // verifyFBToken
    app.get('/notes', verifyFBToken, async (req, res) => {
      const { email } = req.query;
      if (!email) {
        return res.status(400).send({ message: 'Email query parameter is required' });
      }
      const result = await notesCollection.find({ email }).toArray();
      res.send(result);
    });

    // POST: Create a new note
    app.post('/notes', verifyFBToken, async (req, res) => {
      try {
        const { email, title, description, created_at } = req.body;
        if (!email || !title || !description) {
          return res.status(400).send({ message: 'Email, title, and description are required' });
        }
        const note = { email, title, description, created_at: created_at || new Date().toISOString() };
        const result = await notesCollection.insertOne(note);
        res.send({ success: true, noteId: result.insertedId });
      } catch (error) {
        console.error('Error creating note:', error);
        res.status(500).send({ message: 'Failed to create note' });
      }
    });

    // DELETE: Delete a note by ID
    app.delete('/notes/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const result = await notesCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Note not found' });
        }
        res.send({ success: true });
      } catch (error) {
        console.error('Error deleting note:', error);
        res.status(500).send({ message: 'Failed to delete note' });
      }
    });

    // PATCH: Update a note by ID
    app.patch('/notes/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { title, description } = req.body;
        if (!title && !description) {
          return res.status(400).send({ message: 'Nothing to update' });
        }
        const updateDoc = {};
        if (title) updateDoc.title = title;
        if (description) updateDoc.description = description;
        const result = await notesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Note not found' });
        }
        res.send({ success: true });
      } catch (error) {
        console.error('Error updating note:', error);
        res.status(500).send({ message: 'Failed to update note' });
      }
    });


    // **Sessions**

    // GET: Public route for available study sessions (limit , only approved)
    app.get('/available-sessions', async (req, res) => {
      try {
        const sessions = await sessionsCollection
          .find({ status: 'approved' })
          .sort({ registrationEnd: 1 }) // soonest closing first
          .limit(8)
          .project({ title: 1, description: 1, registrationFee: 1, registrationStart: 1, registrationEnd: 1, sessionImage: 1, tutorName: 1, duration: 1 })
          .toArray();
        res.send(sessions);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch available sessions' });
      }
    });

    // Public: Get all study sessions with pagination (no auth, show all statuses, hide tutorEmail)
    app.get('/public-sessions', async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 8;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalItems = await sessionsCollection.countDocuments({});
        const totalPages = Math.ceil(totalItems / limit);

        // Get paginated sessions
        const sessions = await sessionsCollection
          .find({ status: 'approved' })
          .project({ tutorEmail: 0 })
          .sort({ registrationEnd: 1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          sessions,
          totalPages,
          totalItems,
          currentPage: page,
          itemsPerPage: limit
        });
      } catch (error) {
        console.error('Error fetching sessions:', error);
        res.status(500).send({ message: 'Failed to fetch sessions' });
      }
    });

    // GET: Get all sessions for a tutor by email, or all sessions for admin
    app.get('/sessions', verifyFBToken, async (req, res) => {
      try {
        const { email } = req.query;
        const userEmail = req.decoded.email;
        let query = {};

        // Check if user is admin or tutor
        const user = await usersCollection.findOne({ email: userEmail });
        if (user && user.role === 'admin') {
          // Admin can see all sessions or filter by specific tutor email
          if (email) {
            query.tutorEmail = email;
          }
        } else if (user && user.role === 'tutor') {
          // Tutor can only see their own sessions
          query.tutorEmail = userEmail;
        } else {
          // Students or other roles cannot access sessions
          return res.status(403).send({ message: 'forbidden access' });
        }

        // Pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const totalItems = await sessionsCollection.countDocuments(query);
        const totalPages = Math.ceil(totalItems / limit);

        const sessions = await sessionsCollection
          .find(query)
          .sort({ registrationEnd: 1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          sessions,
          totalPages,
          totalItems,
          currentPage: page,
          itemsPerPage: limit
        });
      } catch (error) {
        console.error('Error fetching sessions:', error);
        res.status(500).send({ message: 'Failed to fetch sessions' });
      }
    });

    // GET: Get a single session by ID
    app.get('/sessions/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const session = await sessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send(session);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch session' });
      }
    });

    // POST: Create a new study session
    app.post('/sessions', verifyFBToken, async (req, res) => {
      try {
        const session = req.body;
        // Basic validation
        if (!session.title || !session.tutorName || !session.tutorEmail || !session.description || !session.registrationStart || !session.registrationEnd || !session.classStart || !session.classEnd || !session.duration) {
          return res.status(400).send({ message: 'Missing required fields' });
        }
        // Set defaults if not provided
        if (!session.registrationFee) session.registrationFee = 0;
        if (!session.status) session.status = 'pending';
        session.created_at = session.created_at || new Date().toISOString();
        const result = await sessionsCollection.insertOne(session);
        res.send({ success: true, sessionId: result.insertedId });
      } catch (error) {
        console.error('Error creating session:', error);
        res.status(500).send({ message: 'Failed to create session' });
      }
    });

    // PATCH: Update session status by ID (approve/reject, set paid/registrationFee) - ADMIN ONLY
    app.patch('/sessions/:id/status', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { status, paid, registrationFee, reason, feedback } = req.body;
        if (!status) return res.status(400).send({ message: 'Status is required' });

        const updateDoc = { status };
        if (status === 'approved') {
          updateDoc.paid = !!paid;
          updateDoc.registrationFee = paid ? Number(registrationFee) : 0;
          updateDoc.rejectionReason = '';
          updateDoc.rejectionFeedback = '';
        }
        if (status === 'rejected') {
          updateDoc.rejectionReason = reason || '';
          updateDoc.rejectionFeedback = feedback || '';
        }
        if (status === 'pending') {
          updateDoc.rejectionReason = '';
          updateDoc.rejectionFeedback = '';
        }

        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateDoc }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update session status' });
      }
    });

    // PATCH: Resubmit rejected session (TUTOR ONLY)
    app.patch('/sessions/:id/resubmit', verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        // First, check if the session exists and belongs to this tutor
        const session = await sessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }

        // Verify the session belongs to the requesting tutor
        if (session.tutorEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only resubmit your own sessions' });
        }

        // Only allow resubmission if the session is currently rejected
        if (session.status !== 'rejected') {
          return res.status(400).send({ message: 'Only rejected sessions can be resubmitted' });
        }

        // Update the session status to pending
        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: 'pending' } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }

        res.send({ success: true, message: 'Session resubmitted successfully' });
      } catch (error) {
        console.error('Error resubmitting session:', error);
        res.status(500).send({ message: 'Failed to resubmit session' });
      }
    });

    // PUT: Update a session by ID (for admin update)
    app.put('/sessions/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const result = await sessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update session' });
      }
    });

    // DELETE: Delete a session by ID (admin only)
    app.delete('/sessions/:id', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const result = await sessionsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete session' });
      }
    });

    // DELETE: Delete own session by ID (tutor only)
    app.delete('/sessions/:id/own', verifyFBToken, verifyTutor, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        // First check if the session exists and belongs to this tutor
        const session = await sessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }

        // Verify the session belongs to the requesting tutor
        if (session.tutorEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only delete your own sessions' });
        }

        const result = await sessionsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Session not found' });
        }
        res.send({ success: true });
      } catch (error) {
        console.error('Error deleting session:', error);
        res.status(500).send({ message: 'Failed to delete session' });
      }
    });

    // **materials**

    // READ: Get all materials, or filter by sessionId or tutorEmail
    app.get('/materials', verifyFBToken, async (req, res) => {
      try {
        const { sessionId, tutorEmail } = req.query;
        const query = {};
        if (sessionId) query.sessionId = sessionId;
        if (tutorEmail) query.tutorEmail = tutorEmail;
        const materials = await materialsCollection.find(query).toArray();
        res.send(materials);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch materials' });
      }
    });

    // READ: Get a single material by ID
    app.get('/materials/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const material = await materialsCollection.findOne({ _id: new ObjectId(id) });
        if (!material) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send(material);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch material' });
      }
    });

    // CREATE: Upload a new material for a session
    app.post('/materials', verifyFBToken, async (req, res) => {
      try {
        const { title, sessionId, tutorEmail, imageUrl, resourceLink } = req.body;
        if (!title || !sessionId || !tutorEmail || !imageUrl || !resourceLink) {
          return res.status(400).send({ message: 'All fields are required' });
        }
        const material = {
          title,
          sessionId, // string, references the study session
          tutorEmail, // string, the tutor's email
          imageUrl,   // string, link to image (e.g. from ImgBB)
          resourceLink, // string, Google Drive link
          created_at: new Date().toISOString(),
        };
        const result = await materialsCollection.insertOne(material);
        res.send({ success: true, materialId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to upload material' });
      }
    });

    // UPDATE: Update a material by ID
    app.put('/materials/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;
        const result = await materialsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update material' });
      }
    });

    // DELETE: Delete a material by ID
    app.delete('/materials/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const result = await materialsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Material not found' });
        }
        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete material' });
      }
    });

    // **Announcements**

    // GET: Get all announcements
    app.get('/announcements', async (req, res) => {
      try {
        const announcements = await announcementsCollection.find({}).toArray();
        res.send(announcements);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch announcements' });
      }
    });

    // POST: Create a new announcement (admin only)
    app.post('/announcements', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { title, message, category, audience, priority, link, imageUrl } = req.body;
        if (!title || !message) {
          return res.status(400).send({ message: 'Title and message are required' });
        }
        const announcement = {
          title,
          message,
          category: category || '',
          audience: audience || '',
          priority: priority || '',
          link: link || '',
          imageUrl: imageUrl || '',
          created_at: new Date().toISOString(),
        };
        const result = await announcementsCollection.insertOne(announcement);
        res.send({ success: true, announcementId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Failed to create announcement' });
      }
    });

    // **Bookings API**

    // GET: Get all bookings (admin only)
    app.get('/bookedSessions', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const bookings = await bookedSessionsCollection.find({}).toArray();
        res.send(bookings);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch bookings' });
      }
    });

    // GET: Get bookings by student email
    app.get('/bookedSessions/student/:email', verifyFBToken, async (req, res) => {
      try {
        const { email } = req.params;
        const userEmail = req.decoded.email;

        // Students can only see their own bookings
        if (email !== userEmail) {
          return res.status(403).send({ message: 'You can only view your own bookings' });
        }

        const bookings = await bookedSessionsCollection.find({ studentEmail: email }).toArray();
        res.send(bookings);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch bookings' });
      }
    });

    // GET: Get a single booking by ID
    app.get('/bookedSessions/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        const booking = await bookedSessionsCollection.findOne({ _id: new ObjectId(id) });

        if (!booking) {
          return res.status(404).send({ message: 'Booking not found' });
        }

        // Students can only see their own bookings
        if (booking.studentEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only view your own bookings' });
        }

        res.send(booking);
      } catch (error) {
        console.error('Error fetching booking:', error);
        res.status(500).send({ message: 'Failed to fetch booking' });
      }
    });

    // POST: Create a new booking
    app.post('/bookedSessions', verifyFBToken, async (req, res) => {
      try {
        const { sessionId, studentEmail, amount, paymentStatus, paymentMethod } = req.body;
        const userEmail = req.decoded.email;

        // Verify the booking is for the authenticated user
        if (studentEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only book sessions for yourself' });
        }

        if (!sessionId || !studentEmail || amount === undefined) {
          return res.status(400).send({ message: 'Session ID, student email, and amount are required' });
        }

        // Check if session exists and is approved
        const session = await sessionsCollection.findOne({ _id: new ObjectId(sessionId) });
        if (!session) {
          return res.status(404).send({ message: 'Session not found' });
        }

        if (session.status !== 'approved') {
          return res.status(400).send({ message: 'Session is not available for booking' });
        }

        // Check if registration is still open
        const now = new Date();
        const regStart = new Date(session.registrationStart);
        const regEnd = new Date(session.registrationEnd);
        if (now < regStart || now > regEnd) {
          return res.status(400).send({ message: 'Registration period is not open' });
        }

        // Check if student already booked this session
        const existingBooking = await bookedSessionsCollection.findOne({
          sessionId: sessionId,
          studentEmail: studentEmail
        });

        if (existingBooking) {
          return res.status(400).send({ message: 'You have already booked this session' });
        }

        const booking = {
          sessionId,
          studentEmail,
          amount: Number(amount),
          paymentStatus: paymentStatus || 'pending',
          paymentMethod: paymentMethod || 'card',
          bookedAt: new Date().toISOString(),
          sessionDetails: {
            title: session.title,
            tutorName: session.tutorName,
            classStart: session.classStart,
            classEnd: session.classEnd,
            duration: session.duration
          }
        };

        const result = await bookedSessionsCollection.insertOne(booking);
        res.send({ success: true, bookingId: result.insertedId });
      } catch (error) {
        console.error('Error creating booking:', error);
        res.status(500).send({ message: 'Failed to create booking' });
      }
    });

    // PATCH: Update booking payment status
    app.patch('/bookedSessions/:id/payment', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { paymentStatus, transactionId } = req.body;
        const userEmail = req.decoded.email;

        if (!paymentStatus) {
          return res.status(400).send({ message: 'Payment status is required' });
        }

        // Find booking and verify ownership
        const booking = await bookedSessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!booking) {
          return res.status(404).send({ message: 'Booking not found' });
        }

        if (booking.studentEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only update your own bookings' });
        }

        const updateData = { paymentStatus };
        if (transactionId) {
          updateData.transactionId = transactionId;
        }

        const result = await bookedSessionsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Booking not found' });
        }

        res.send({ success: true });
      } catch (error) {
        res.status(500).send({ message: 'Failed to update booking payment status' });
      }
    });

    // DELETE: Cancel a booking by ID (student only)
    app.delete('/bookedSessions/:id/cancel', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        // Find booking and verify ownership
        const booking = await bookedSessionsCollection.findOne({ _id: new ObjectId(id) });
        if (!booking) {
          return res.status(404).send({ message: 'Booking not found' });
        }
        if (booking.studentEmail !== userEmail) {
          return res.status(403).send({ message: 'You can only cancel your own bookings' });
        }

        // Delete the booking
        const result = await bookedSessionsCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Booking not found' });
        }

        res.send({ success: true });
      } catch (error) {
        console.error('Error cancelling booking:', error);
        res.status(500).send({ message: 'Failed to cancel booking' });
      }
    });
    // **Payments API**

    // GET: Get payment history for a user
    app.get('/payments', verifyFBToken, async (req, res) => {
      try {
        const userEmail = req.query.email;
        // console.log('decoded', req.decoded);
        if (req.decoded.email !== userEmail) {
          return res.status(403).send({ message: 'forbidden access' });
        }

        const query = userEmail ? { email: userEmail } : {};
        const options = { sort: { paid_at: -1 } }; // Latest first

        const payments = await paymentsCollection.find(query, options).toArray();
        res.send(payments);
      } catch (error) {
        console.error('Error fetching payment history:', error);
        res.status(500).send({ message: 'Failed to get payments' });
      }
    });

    // POST: Record payment and update booking status
    app.post('/payments', verifyFBToken, async (req, res) => {
      try {
        const { bookingId, email, amount, paymentMethod, transactionId } = req.body;

        // 1. Update booking's payment status
        const updateResult = await bookedSessionsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          {
            $set: {
              paymentStatus: 'completed',
              transactionId: transactionId
            }
          }
        );

        if (updateResult.modifiedCount === 0) {
          return res.status(404).send({ message: 'Booking not found or already paid' });
        }

        // 2. Insert payment record
        const paymentDoc = {
          bookingId,
          email,
          amount,
          paymentMethod,
          transactionId,
          paid_at_string: new Date().toISOString(),
          paid_at: new Date(),
        };

        const paymentResult = await paymentsCollection.insertOne(paymentDoc);

        res.status(201).send({
          message: 'Payment recorded and booking marked as paid',
          insertedId: paymentResult.insertedId,
        });

      } catch (error) {
        console.error('Payment processing failed:', error);
        res.status(500).send({ message: 'Failed to record payment' });
      }
    });

    // POST: Create payment intent for Stripe
    app.post('/create-payment-intent', async (req, res) => {
      try {
        const { amountInCents } = req.body;

        if (!amountInCents || amountInCents <= 0) {
          return res.status(400).json({ error: 'Invalid amount' });
        }

        // console.log('Creating payment intent for amount:', amountInCents, 'cents');

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amountInCents, // Amount in cents
          currency: 'usd',
          payment_method_types: ['card'],
          metadata: {
            integration_check: 'accept_a_payment',
          },
        });

        // console.log('Payment intent created:', paymentIntent.id);
        res.json({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).json({ error: error.message });
      }
    });

    // **Reviews API**

    // GET: Get reviews for a specific session
    app.get('/reviews/session/:sessionId', async (req, res) => {
      try {
        const { sessionId } = req.params;

        if (!sessionId) {
          return res.status(400).send({ message: 'Session ID is required' });
        }

        const reviews = await reviewsCollection
          .find({ sessionId })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(reviews);
      } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).send({ message: 'Failed to fetch reviews' });
      }
    });

    // POST: Submit a new review
    app.post('/reviews', verifyFBToken, async (req, res) => {
      try {
        const { sessionId, studentName, studentEmail, studentPhoto, isVerified, rating, comment } = req.body;
        const userEmail = req.decoded.email;

        // Validate required fields
        if (!sessionId || !rating || !comment) {
          return res.status(400).send({ message: 'Session ID, rating, and comment are required' });
        }

        if (rating < 1 || rating > 5) {
          return res.status(400).send({ message: 'Rating must be between 1 and 5' });
        }

        // Check if user has already reviewed this session
        const existingReview = await reviewsCollection.findOne({
          sessionId,
          studentEmail: userEmail
        });

        if (existingReview) {
          return res.status(400).send({ message: 'You have already reviewed this session' });
        }

        // Create review document
        const reviewDoc = {
          sessionId,
          studentName: studentName || 'Anonymous',
          studentEmail: userEmail,
          studentPhoto: studentPhoto || null,
          isVerified: isVerified || false,
          rating: parseInt(rating),
          comment: comment.trim(),
          createdAt: new Date().toISOString(),
          created_at: new Date()
        };

        const result = await reviewsCollection.insertOne(reviewDoc);

        res.status(201).send({
          success: true,
          reviewId: result.insertedId,
          message: 'Review submitted successfully'
        });

      } catch (error) {
        console.error('Error submitting review:', error);
        res.status(500).send({ message: 'Failed to submit review' });
      }
    });

    // GET: Get all reviews (admin only)
    app.get('/reviews', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { sessionId, search } = req.query;
        let query = {};

        if (sessionId) {
          query.sessionId = sessionId;
        }

        if (search) {
          query.$or = [
            { studentName: { $regex: search, $options: 'i' } },
            { comment: { $regex: search, $options: 'i' } }
          ];
        }

        const reviews = await reviewsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();

        res.send(reviews);
      } catch (error) {
        console.error('Error fetching all reviews:', error);
        res.status(500).send({ message: 'Failed to fetch reviews' });
      }
    });

    // DELETE: Delete a review (admin only or review owner)
    app.delete('/reviews/:id', verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const userEmail = req.decoded.email;

        // Find the review
        const review = await reviewsCollection.findOne({ _id: new ObjectId(id) });
        if (!review) {
          return res.status(404).send({ message: 'Review not found' });
        }

        // Check if user is admin or review owner
        const user = await usersCollection.findOne({ email: userEmail });
        if (!user || (user.role !== 'admin' && review.studentEmail !== userEmail)) {
          return res.status(403).send({ message: 'You can only delete your own reviews or must be admin' });
        }

        const result = await reviewsCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Review not found' });
        }

        res.send({ success: true, message: 'Review deleted successfully' });
      } catch (error) {
        console.error('Error deleting review:', error);
        res.status(500).send({ message: 'Failed to delete review' });
      }
    });

    // GET: Admin statistics (admin only)
    app.get('/admin/statistics', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        // Total users
        const totalUsers = await usersCollection.countDocuments({});
        // Total tutors
        const totalTutors = await usersCollection.countDocuments({ role: 'tutor' });
        // Total students
        const totalStudents = await usersCollection.countDocuments({ role: 'student' });
        // Total sessions
        const totalSessions = await sessionsCollection.countDocuments({});
        // Total bookings
        const totalBookings = await bookedSessionsCollection.countDocuments({});
        // Average rating (across all reviews)
        const allReviews = await reviewsCollection.find({}).toArray();
        const averageRating = allReviews.length > 0
          ? (allReviews.reduce((sum, r) => sum + (Number(r.rating) || 0), 0) / allReviews.length).toFixed(2)
          : 0;

        res.send({
          totalUsers,
          totalTutors,
          totalStudents,
          totalSessions,
          totalBookings,
          averageRating
        });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch admin statistics' });
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("That's great! Server is running");
});

app.listen(port, (req, res) => {
  console.log(`Server is running on port http://localhost:${port}`);
});
