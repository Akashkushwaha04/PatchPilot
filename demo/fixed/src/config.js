// Front-end configuration. Contains no secrets: AI calls go through our own API.
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

// The "Describe my listing" helper calls /api/ai/describe on our server.
export const AI_DESCRIBE_ENDPOINT = `${API_BASE_URL}/api/ai/describe`;

export const FEATURES = {
  aiDescriptions: true,
};
