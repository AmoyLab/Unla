import api from './api';

export const getSystemPrompt = async (): Promise<string> => {
  const response = await api.get('/chat/systemprompt');
  return response.data.data?.prompt || '';
};

export const saveSystemPrompt = async (prompt: string): Promise<void> => {
  await api.put('/chat/systemprompt', { prompt });
};
