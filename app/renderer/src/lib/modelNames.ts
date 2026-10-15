import type { ProviderCatalog, ProviderConnection } from "./api";

export function modelName(id: string, catalog?: ProviderCatalog, provider?: string): string {
  const listed = catalog?.providers.find((item) => item.id === provider)?.models.find((model) => model.id === id);
  if (listed?.name && listed.name !== id) return listed.name;
  return id.replace(/[-_]/g, " ").replace(/\b(glm|gpt|claude|qwen|deepseek|sonnet|opus|haiku|gemini|codex)\b/gi,
    (part) => /^(glm|gpt)$/i.test(part) ? part.toUpperCase() : part[0]!.toUpperCase() + part.slice(1));
}

export function connectionName(item: ProviderConnection, catalog?: ProviderCatalog): string {
  return modelName(item.model, catalog, item.provider);
}
