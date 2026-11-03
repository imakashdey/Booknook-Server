require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose");

const app = express();
const PORT = process.env.PORT || 5000;
const BORROW_DAYS = 7;

app.use(
  cors({
    origin: (process.env.CLIENT_URL || "http://localhost:3000").split(","),
    credentials: true,
  })
);
app.use(express.json());

// ---------- MongoDB (connection cached for serverless hosts) ----------
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let booksCol;
let borrowsCol;
async function connectDB() {
  if (booksCol && borrowsCol) return;
  await client.connect();
  const db = client.db(process.env.DB_NAME || "booknook");
  booksCol = db.collection("books");
  borrowsCol = db.collection("borrows");
}

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).send({ message: "Database connection failed" });
  }
});

// ---------- JWT verification (tokens issued by BetterAuth jwt plugin) ----------
// The Next.js client exposes its public keys at /api/auth/jwks
let jwks;
function getJwks() {
  if (!jwks) {
    const base = (process.env.AUTH_URL || "http://localhost:3000").replace(/\/$/, "");
    jwks = createRemoteJWKSet(new URL(`${base}/api/auth/jwks`));
  }
  return jwks;
}

async function verifyJWT(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized: token missing" });
  }
  try {
    const { payload } = await jwtVerify(header.slice(7), getJwks());
    if (!payload.email) {
      return res.status(401).send({ message: "Unauthorized: invalid token" });
    }
    req.user = { email: payload.email, name: payload.name };
    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized: invalid or expired token" });
  }
}

function toObjectId(id) {
  return ObjectId.isValid(id) ? new ObjectId(id) : null;
}

function isHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// ---------- Health ----------
app.get("/", (req, res) => res.send({ message: "BookNook server is running" }));

// ---------- BOOKS ----------

// 1) GET /books  (public) ?limit=6&sort=newest&email=<owner>&category=Fiction&search=term
app.get("/books", async (req, res) => {
  try {
    const { limit, sort, email, category, search } = req.query;
    const query = {};
    if (email) query.addedByEmail = email;
    if (category && category !== "All") query.category = category;
    if (search) {
      const rx = new RegExp(String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      query.$or = [{ title: rx }, { author: rx }];
    }

    let cursor = booksCol.find(query);
    if (sort === "newest") cursor = cursor.sort({ createdAt: -1 });
    const lim = parseInt(limit, 10);
    if (lim > 0) cursor = cursor.limit(lim);

    res.send(await cursor.toArray());
  } catch (err) {
    res.status(500).send({ message: "Failed to load books" });
  }
});

// 2) GET /books/:id  (private)
app.get("/books/:id", verifyJWT, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(400).send({ message: "Invalid book id" });
    const book = await booksCol.findOne({ _id });
    if (!book) return res.status(404).send({ message: "Book not found" });
    res.send(book);
  } catch (err) {
    res.status(500).send({ message: "Failed to load book" });
  }
});

// 3) POST /books  (private)
app.post("/books", verifyJWT, async (req, res) => {
  try {
    const { title, author, category, image, description, totalCopies, addedByName } = req.body;
    const copies = parseInt(totalCopies, 10);

    if (!title || !author || !category || !image || !description) {
      return res.status(400).send({ message: "All fields are required" });
    }
    if (!isHttpUrl(image)) {
      return res.status(400).send({ message: "Image must be a valid http or https URL" });
    }
    if (!Number.isInteger(copies) || copies < 1) {
      return res.status(400).send({ message: "Total copies must be at least 1" });
    }

    const book = {
      title: title.trim(),
      author: author.trim(),
      category,
      image,
      description: description.trim(),
      totalCopies: copies,
      availableCopies: copies,
      addedByName: addedByName || req.user.name || "Unknown",
      addedByEmail: req.user.email, // always taken from the verified token
      createdAt: new Date(),
    };
    const result = await booksCol.insertOne(book);
    res.status(201).send({ ...book, _id: result.insertedId });
  } catch (err) {
    res.status(500).send({ message: "Failed to add book" });
  }
});

// 4) PATCH /books/:id  (private, owner only)
app.patch("/books/:id", verifyJWT, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(400).send({ message: "Invalid book id" });

    const book = await booksCol.findOne({ _id });
    if (!book) return res.status(404).send({ message: "Book not found" });
    if (book.addedByEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: you can only edit your own books" });
    }

    const { title, author, category, image, description, totalCopies } = req.body;
    const $set = {};
    if (title) $set.title = title.trim();
    if (author) $set.author = author.trim();
    if (category) $set.category = category;
    if (image) {
      if (!isHttpUrl(image)) {
        return res.status(400).send({ message: "Image must be a valid http or https URL" });
      }
      $set.image = image;
    }
    if (description) $set.description = description.trim();

    if (totalCopies !== undefined) {
      const copies = parseInt(totalCopies, 10);
      const borrowedNow = book.totalCopies - book.availableCopies;
      if (!Number.isInteger(copies) || copies < Math.max(1, borrowedNow)) {
        return res.status(400).send({
          message: `Total copies cannot be less than the ${borrowedNow} currently borrowed`,
        });
      }
      $set.totalCopies = copies;
      $set.availableCopies = copies - borrowedNow;
    }

    if (Object.keys($set).length === 0) {
      return res.status(400).send({ message: "Nothing to update" });
    }
    $set.updatedAt = new Date();

    await booksCol.updateOne({ _id }, { $set });
    res.send(await booksCol.findOne({ _id }));
  } catch (err) {
    res.status(500).send({ message: "Failed to update book" });
  }
});

// 5) DELETE /books/:id  (private, owner only)
app.delete("/books/:id", verifyJWT, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(400).send({ message: "Invalid book id" });

    const book = await booksCol.findOne({ _id });
    if (!book) return res.status(404).send({ message: "Book not found" });
    if (book.addedByEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: you can only delete your own books" });
    }

    await booksCol.deleteOne({ _id });
    await borrowsCol.deleteMany({ bookId: String(_id) }); // clean up related borrows
    res.send({ message: "Book deleted", deletedCount: 1 });
  } catch (err) {
    res.status(500).send({ message: "Failed to delete book" });
  }
});

// ---------- BORROWS ----------

// 6) POST /borrows  (private) body: { bookId }
app.post("/borrows", verifyJWT, async (req, res) => {
  try {
    const { bookId } = req.body;
    const _id = toObjectId(bookId);
    if (!_id) return res.status(400).send({ message: "Invalid book id" });

    const userEmail = req.user.email;

    // No double borrow
    const already = await borrowsCol.findOne({ bookId: String(_id), userEmail });
    if (already) {
      return res.status(409).send({ message: "You have already borrowed this book" });
    }

    // Atomically take one copy (only if any are left)
    const updated = await booksCol.findOneAndUpdate(
      { _id, availableCopies: { $gt: 0 } },
      { $inc: { availableCopies: -1 } },
      { returnDocument: "after" }
    );
    if (!updated) {
      const exists = await booksCol.findOne({ _id }, { projection: { _id: 1 } });
      return exists
        ? res.status(400).send({ message: "Sorry, this book is not available right now" })
        : res.status(404).send({ message: "Book not found" });
    }

    const borrowDate = new Date();
    const returnDate = new Date(borrowDate.getTime() + BORROW_DAYS * 24 * 60 * 60 * 1000);
    const borrow = {
      bookId: String(_id),
      bookTitle: updated.title,
      bookImage: updated.image,
      userEmail,
      userName: req.user.name || req.body.userName || "",
      borrowDate,
      returnDate,
    };

    try {
      const result = await borrowsCol.insertOne(borrow);
      res.status(201).send({ ...borrow, _id: result.insertedId });
    } catch (insertErr) {
      // put the copy back if saving the borrow failed
      await booksCol.updateOne({ _id }, { $inc: { availableCopies: 1 } });
      throw insertErr;
    }
  } catch (err) {
    res.status(500).send({ message: "Failed to borrow book" });
  }
});

// 7) GET /borrows  (private) -> only the logged in user's borrows
app.get("/borrows", verifyJWT, async (req, res) => {
  try {
    const borrows = await borrowsCol
      .find({ userEmail: req.user.email })
      .sort({ borrowDate: -1 })
      .toArray();
    res.send(borrows);
  } catch (err) {
    res.status(500).send({ message: "Failed to load borrows" });
  }
});

// 8) DELETE /borrows/:id  (private) -> return a book
app.delete("/borrows/:id", verifyJWT, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(400).send({ message: "Invalid borrow id" });

    const borrow = await borrowsCol.findOne({ _id });
    if (!borrow) return res.status(404).send({ message: "Borrow record not found" });
    if (borrow.userEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: this is not your borrow" });
    }

    await borrowsCol.deleteOne({ _id });
    await booksCol.updateOne({ _id: new ObjectId(borrow.bookId) }, { $inc: { availableCopies: 1 } });
    res.send({ message: "Book returned", deletedCount: 1 });
  } catch (err) {
    res.status(500).send({ message: "Failed to return book" });
  }
});

// 404 for unknown API routes
app.use((req, res) => res.status(404).send({ message: "Route not found" }));

// Global error handler (bad JSON bodies and anything unexpected)
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).send({ message: "Invalid JSON body" });
  }
  console.error(err);
  res.status(500).send({ message: "Something went wrong on the server" });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`BookNook server running on port ${PORT}`));
}

module.exports = app; // for Vercel serverless