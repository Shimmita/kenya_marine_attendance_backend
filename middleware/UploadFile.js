import multer from "multer";

const storage = multer.memoryStorage();

const uploadAvatar = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024 }, // 3MB
});

export default uploadAvatar;