import OpenAI from 'openai';

export async function analyzeWithOpenAI(request: {
  model: string;
  apiKey: string;
  systemPrompt: string;
  userPrompt: string;
}): Promise<{
  text: string;
  inputTokens: number;
  outputTokens: number;
}> {
  const client = new OpenAI({ apiKey: request.apiKey });

  const response = await client.chat.completions.create({
    model: request.model,
    temperature: 0,
    max_completion_tokens: 600,
    messages: [
      {
        role: 'system',
        content: request.systemPrompt,
      },
      {
        role: 'user',
        content: request.userPrompt,
      },
    ],
  });

  return {
    text: response.choices[0]?.message?.content?.trim() ?? '',
    inputTokens: response.usage?.prompt_tokens ?? 0,
    outputTokens: response.usage?.completion_tokens ?? 0,
  };
}
