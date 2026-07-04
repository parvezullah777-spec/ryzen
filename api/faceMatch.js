/* ── Local face comparison — no external API, runs inside this function ── */
/*
 * Uses @vladmandic/face-api (a maintained face-api.js fork) on top of
 * @tensorflow/tfjs-node. Everything happens on your own server; no photo
 * or descriptor is ever sent to a third party.
 *
 * SETUP (one-time):
 *   1. npm install @vladmandic/face-api @tensorflow/tfjs-node
 *   2. Download these model files and place them in a `models/` folder
 *      next to this file (same directory):
 *        - ssd_mobilenetv1_model-weights_manifest.json + shard1.bin
 *        - face_landmark_68_model-weights_manifest.json + shard1.bin
 *        - face_recognition_model-weights_manifest.json + shard1.bin + shard2.bin
 *      Get them from: https://github.com/vladmandic/face-api/tree/master/model
 *      (download the whole `model` folder — it's a few MB total)
 *   3. Commit the `models/` folder to your repo so Vercel deploys it.
 */

const path = require('path');

let faceapi;
let tf;
let modelsLoaded = false;

function lazyRequire() {
  if (!faceapi) faceapi = require('@vladmandic/face-api');
  if (!tf) tf = require('@tensorflow/tfjs-node');
}

async function loadModels() {
  if (modelsLoaded) return;
  lazyRequire();
  const MODELS_PATH = path.join(__dirname, 'models');
  await faceapi.nets.ssdMobilenetv1.loadFromDisk(MODELS_PATH);
  await faceapi.nets.faceLandmark68Net.loadFromDisk(MODELS_PATH);
  await faceapi.nets.faceRecognitionNet.loadFromDisk(MODELS_PATH);
  modelsLoaded = true;
}

function cleanImage(base64Data) {
  return base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
}

async function getDescriptor(base64Image) {
  const buffer = Buffer.from(cleanImage(base64Image), 'base64');
  const decoded = tf.node.decodeImage(buffer, 3);
  // decodeImage returns a 3D tensor [height, width, channels]. face-api.js's
  // internal ops expect a 4D batched tensor [1, height, width, channels].
  const tensor = decoded.expandDims(0);
  try {
    const detection = await faceapi
      .detectSingleFace(tensor)
      .withFaceLandmarks()
      .withFaceDescriptor();
    return detection ? detection.descriptor : null;
  } finally {
    decoded.dispose();
    tensor.dispose();
  }
}

/**
 * Compares two base64 images and returns the same shape the old
 * Face++ function returned, so the rest of admin.js doesn't need to change:
 *   { match: boolean, confidence: number, reason: string }
 */
async function verifyFaceLocally(referenceImage, capturedImage) {
  await loadModels();

  const refDescriptor = await getDescriptor(referenceImage);
  if (!refDescriptor) {
    return { match: false, confidence: 0, reason: 'No face detected in the enrolled reference photo.' };
  }

  const capDescriptor = await getDescriptor(capturedImage);
  if (!capDescriptor) {
    return { match: false, confidence: 0, reason: 'No face detected in the login snapshot.' };
  }

  const distance = faceapi.euclideanDistance(refDescriptor, capDescriptor);
  // face-api.js convention: distance < 0.6 is the usual "same person" threshold.
  // We use a stricter bar since this gates admin access.
  const MAX_DISTANCE = 0.5;
  const confidence = Math.max(0, Math.round((1 - distance) * 100));

  return {
    match: distance < MAX_DISTANCE,
    confidence,
    reason: distance < MAX_DISTANCE ? 'Face matched.' : 'Face did not match closely enough.',
  };
}

module.exports = { verifyFaceLocally };
