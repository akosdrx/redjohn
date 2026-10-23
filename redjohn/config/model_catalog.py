"""Curated model providers for the TUI ``/models`` picker.

The menu is the provider list, not every model on the internet. After a
provider accepts a key or a sign-in, its own ``/models`` endpoint supplies the
choices. A short built-in list is used only when that endpoint does not answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

import requests


Route = Literal["openai", "anthropic", "xai", "chatgpt", "grok", "litellm"]
AuthKind = Literal["api_key", "oauth_browser", "oauth_device", "custom_endpoint"]

EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")


@dataclass(frozen=True)
class ModelEffortSpec:
    default_effort: str
    supported_efforts: tuple[str, ...]
    supports_reasoning: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_effort": self.default_effort,
            "supported_efforts": list(self.supported_efforts),
            "supports_reasoning": self.supports_reasoning,
        }


_FETCH_TIMEOUT = (5, 12)
_MAX_MODELS = 80
_NON_CHAT_MARKERS = (
    "embedding",
    "embed-",
    "whisper",
    "tts",
    "dall-e",
    "moderation",
    "realtime",
    "transcribe",
    "audio",
    "image",
    "sora",
)


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    label: str
    auth: AuthKind | None = None
    route: Route = "openai"
    api_base: str | None = None
    fallback_models: tuple[str, ...] = ()
    children: tuple[CatalogEntry, ...] = ()

    def public(self) -> dict[str, Any]:
        """The fields the TUI renders. Routes and keys stay on the backend."""
        payload: dict[str, Any] = {"id": self.id, "label": self.label, "auth": self.auth or ""}
        if self.children:
            payload["children"] = [child.public() for child in self.children]
        return payload


_XIAOMI_MODELS = (
    "mimo-v2.6-pro",
    "mimo-v2.6-flash",
    "mimo-v2.5-pro",
    "mimo-v2.5",
    "mimo-v2-pro",
    "mimo-v2-flash",
)
_CHATGPT_MODELS = ("gpt-5.4", "gpt-5.3-codex", "gpt-5.2", "gpt-5.1-codex", "gpt-5")
_OPENAI_MODELS = ("gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex", "gpt-4.1", "o3", "o4-mini")
_ANTHROPIC_MODELS = ("claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5")
_XAI_MODELS = ("grok-4", "grok-4-fast", "grok-3", "grok-code-fast-1")
_ZAI_MODELS = ("glm-5.3", "glm-5", "glm-4.6", "glm-4.5", "glm-4.5-air")
_QWEN_MODELS = ("qwen3-coder-plus", "qwen3-235b-a22b", "qwen3-32b", "qwq-32b", "qwen-max")
_DEEPSEEK_MODELS = ("deepseek-reasoner", "deepseek-chat", "deepseek-r1", "deepseek-v3")
_GEMINI_MODELS = ("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash")
_KIMI_MODELS = ("kimi-for-coding", "kimi-k2-thinking", "kimi-k2-instruct", "moonshot-v1-128k")
_MINIMAX_MODELS = ("MiniMax-M2", "MiniMax-M1", "MiniMax-Text-01")
_MISTRAL_MODELS = ("mistral-large-latest", "codestral-latest", "magistral-medium-latest")
_OPENROUTER_MODELS = (
    "anthropic/claude-opus-4-7",
    "anthropic/claude-sonnet-4-6",
    "openai/gpt-5.4",
    "google/gemini-2.5-pro",
    "deepseek/deepseek-r1",
    "qwen/qwen3-coder",
    "z-ai/glm-5",
)
_GENERIC_CODING_MODELS = (
    "qwen3-coder-plus",
    "glm-5",
    "deepseek-r1",
    "deepseek-v3",
    "claude-sonnet-4-6",
    "gpt-5.4",
    "llama-3.3-70b-instruct",
)


def _xiaomi(entry_id: str, label: str, api_base: str) -> CatalogEntry:
    return CatalogEntry(
        id=entry_id,
        label=label,
        auth="api_key",
        route="openai",
        api_base=api_base,
        fallback_models=_XIAOMI_MODELS,
    )


def _provider(
    entry_id: str,
    label: str,
    api_base: str | None = None,
    *,
    route: Route = "openai",
    auth: AuthKind = "api_key",
    fallback_models: tuple[str, ...] = _GENERIC_CODING_MODELS,
) -> CatalogEntry:
    return CatalogEntry(
        id=entry_id,
        label=label,
        auth=auth,
        route=route,
        api_base=api_base,
        fallback_models=fallback_models,
    )


_OPENAI = CatalogEntry(
    id="openai",
    label="OpenAI",
    children=(
        CatalogEntry(
            id="openai.chatgpt",
            label="Sign in with ChatGPT",
            auth="oauth_browser",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.codex-browser",
            label="Codex Browser (Legacy)",
            auth="oauth_browser",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.codex-device",
            label="Codex Device Code (Legacy)",
            auth="oauth_device",
            route="chatgpt",
            fallback_models=_CHATGPT_MODELS,
        ),
        CatalogEntry(
            id="openai.api-key",
            label="API Key",
            auth="api_key",
            route="openai",
            api_base="https://api.openai.com/v1",
            fallback_models=_OPENAI_MODELS,
        ),
    ),
)

_XIAOMI = CatalogEntry(
    id="xiaomi",
    label="Xiaomi",
    children=(
        _xiaomi("xiaomi.api", "API", "https://api.xiaomimimo.com/v1"),
        _xiaomi("xiaomi.cn", "Token Plan (China)", "https://token-plan-cn.xiaomimimo.com/v1"),
        _xiaomi("xiaomi.eu", "Token Plan (Europe)", "https://token-plan-ams.xiaomimimo.com/v1"),
        _xiaomi(
            "xiaomi.sg",
            "Token Plan (Singapore)",
            "https://token-plan-sgp.xiaomimimo.com/v1",
        ),
    ),
)

_XAI = CatalogEntry(
    id="xai",
    label="xAI",
    children=(
        CatalogEntry(
            id="xai.subscription",
            label="SuperGrok Subscription",
            auth="oauth_device",
            route="grok",
            api_base="https://cli-chat-proxy.grok.com/v1",
            fallback_models=_XAI_MODELS,
        ),
        CatalogEntry(
            id="xai.api-key",
            label="API Key",
            auth="api_key",
            route="xai",
            api_base="https://api.x.ai/v1",
            fallback_models=_XAI_MODELS,
        ),
    ),
)


RECOMMENDED: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="abliteration",
        label="abliteration.ai",
        auth="api_key",
        api_base="https://api.abliteration.ai/v1",
        fallback_models=("abliterated-qwen3-coder", "abliterated-glm-5", "abliterated-deepseek-r1"),
    ),
    CatalogEntry(
        id="zai",
        label="z.ai",
        auth="api_key",
        api_base="https://api.z.ai/api/paas/v4",
        fallback_models=_ZAI_MODELS,
    ),
    CatalogEntry(
        id="zai-coding",
        label="z.ai coding plan",
        auth="api_key",
        api_base="https://api.z.ai/api/coding/paas/v4",
        fallback_models=_ZAI_MODELS,
    ),
    CatalogEntry(
        id="venice",
        label="Venice AI",
        auth="api_key",
        api_base="https://api.venice.ai/api/v1",
        fallback_models=("qwen3-235b", "deepseek-r1-671b", "llama-3.3-70b", "venice-uncensored"),
    ),
)

OTHER: tuple[CatalogEntry, ...] = (
    _OPENAI,
    CatalogEntry(
        id="anthropic",
        label="Anthropic",
        auth="api_key",
        route="anthropic",
        api_base="https://api.anthropic.com/v1",
        fallback_models=_ANTHROPIC_MODELS,
    ),
    CatalogEntry(
        id="kimi-ai",
        label="Kimi for Coding (kimi.ai)",
        auth="api_key",
        api_base="https://api.kimi.ai/coding/v1",
        fallback_models=_KIMI_MODELS,
    ),
    CatalogEntry(
        id="kimi-com",
        label="Kimi for Coding (kimi.com)",
        auth="api_key",
        api_base="https://api.kimi.com/coding/v1",
        fallback_models=_KIMI_MODELS,
    ),
    _XIAOMI,
    _XAI,
    _provider("302ai", "302.AI", "https://api.302.ai/v1"),
    _provider("abacus", "Abacus", "https://routellm.abacus.ai/v1"),
    _provider("aihubmix", "AIHubMix", "https://aihubmix.com/v1"),
    _provider(
        "alibaba",
        "Alibaba",
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        fallback_models=_QWEN_MODELS,
    ),
    _provider(
        "alibaba-cn",
        "Alibaba (China)",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        fallback_models=_QWEN_MODELS,
    ),
    _provider(
        "alibaba-coding",
        "Alibaba Coding Plan",
        "https://coding-intl.dashscope.aliyuncs.com/v1",
        fallback_models=_QWEN_MODELS,
    ),
    _provider(
        "alibaba-coding-cn",
        "Alibaba Coding Plan (China)",
        "https://coding.dashscope.aliyuncs.com/v1",
        fallback_models=_QWEN_MODELS,
    ),
    _provider(
        "amazon-bedrock",
        "Amazon Bedrock",
        None,
        route="litellm",
        fallback_models=(
            "bedrock/anthropic.claude-opus-4-7",
            "bedrock/anthropic.claude-sonnet-4-6",
            "bedrock/us.amazon.nova-pro-v1:0",
        ),
    ),
    _provider(
        "azure",
        "Azure",
        None,
        route="litellm",
        fallback_models=("azure/gpt-5.4", "azure/gpt-4.1", "azure/o3"),
    ),
    _provider(
        "azure-cognitive",
        "Azure Cognitive Services",
        None,
        route="litellm",
        fallback_models=("azure_ai/deepseek-r1", "azure_ai/gpt-5.4", "azure_ai/claude-sonnet-4-6"),
    ),
    _provider("bailing", "Bailing", "https://api.tbox.cn/api/llm/v1"),
    _provider("baseten", "Baseten", "https://inference.baseten.co/v1"),
    _provider("berget-ai", "Berget.AI", "https://api.berget.ai/v1"),
    _provider(
        "cerebras",
        "Cerebras",
        "https://api.cerebras.ai/v1",
        fallback_models=("qwen-3-235b-a22b", "qwen-3-32b", "llama-3.3-70b"),
    ),
    _provider("chutes", "Chutes", "https://llm.chutes.ai/v1"),
    _provider("clarifai", "Clarifai", "https://api.clarifai.com/v2/ext/openai/v1"),
    _provider(
        "cloudferro-sherlock",
        "CloudFerro Sherlock",
        "https://api-sherlock.cloudferro.com/openai/v1",
    ),
    _provider(
        "cloudflare-ai-gateway",
        "Cloudflare AI Gateway",
        "https://gateway.ai.cloudflare.com/v1",
    ),
    _provider(
        "cloudflare-workers-ai",
        "Cloudflare Workers AI",
        "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/ai/v1",
    ),
    _provider(
        "cohere",
        "Cohere",
        "https://api.cohere.ai/compatibility/v1",
        fallback_models=("command-a-03-2025", "command-r-plus-08-2024", "command-r-08-2024"),
    ),
    _provider("cortecs", "Cortecs", "https://api.cortecs.ai/v1"),
    _provider(
        "custom",
        "Custom",
        "http://localhost:8000/v1",
        fallback_models=_GENERIC_CODING_MODELS,
    ),
    _provider("drun-cn", "D.Run (China)", "https://chat.d.run/v1"),
    _provider("deepinfra", "Deep Infra", "https://api.deepinfra.com/v1/openai"),
    _provider(
        "deepseek",
        "DeepSeek",
        "https://api.deepseek.com/v1",
        fallback_models=_DEEPSEEK_MODELS,
    ),
    _provider("digitalocean", "DigitalOcean", "https://inference.do-ai.run/v1"),
    _provider("dinference", "Dinference", "https://api.dinference.com/v1"),
    _provider("evroc", "evroc", "https://models.evroc.com/v1"),
    _provider("fastrouter", "FastRouter", "https://go.fastrouter.ai/api/v1"),
    _provider(
        "fireworks-ai",
        "Fireworks AI",
        "https://api.fireworks.ai/inference/v1",
        fallback_models=(
            "accounts/fireworks/models/qwen3-235b-a22b",
            "accounts/fireworks/models/deepseek-r1",
            "accounts/fireworks/models/glm-5",
        ),
    ),
    _provider("firmware", "Firmware", "https://app.firmware.ai/api/v1"),
    _provider("friendli", "Friendli", "https://api.friendli.ai/serverless/v1"),
    _provider(
        "github-copilot",
        "GitHub Copilot",
        "https://api.githubcopilot.com",
        fallback_models=("claude-sonnet-4.6", "gpt-5.4", "gemini-2.5-pro", "o3"),
    ),
    _provider(
        "github-models",
        "GitHub Models",
        "https://models.github.ai/inference",
        fallback_models=("openai/gpt-5.4", "deepseek/DeepSeek-R1", "xai/grok-3"),
    ),
    _provider(
        "gitlab-duo",
        "GitLab Duo",
        "https://gitlab.com/api/v4/ai/llm/proxy",
        fallback_models=("claude-sonnet-4-6", "claude-opus-4-7", "gpt-5.4"),
    ),
    _provider(
        "google",
        "Google",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        fallback_models=_GEMINI_MODELS,
    ),
    _provider(
        "groq",
        "Groq",
        "https://api.groq.com/openai/v1",
        fallback_models=(
            "qwen/qwen3-32b",
            "deepseek-r1-distill-llama-70b",
            "llama-3.3-70b-versatile",
        ),
    ),
    _provider("helicone", "Helicone", "https://ai-gateway.helicone.ai/v1"),
    _provider("hpc-ai", "HPC-AI", "https://api.hpc-ai.com/v1"),
    _provider(
        "huggingface",
        "Hugging Face",
        "https://router.huggingface.co/v1",
        fallback_models=("Qwen/Qwen3-235B-A22B", "deepseek-ai/DeepSeek-R1", "zai-org/GLM-4.5"),
    ),
    _provider("iflow", "iFlow", "https://apis.iflow.cn/v1"),
    _provider(
        "inception",
        "Inception",
        "https://api.inceptionlabs.ai/v1",
        fallback_models=("mercury-coder-small", "mercury-coder"),
    ),
    _provider("inference", "Inference", "https://api.inference.net/v1"),
    _provider("io-net", "IO.NET", "https://api.intelligence.io.solutions/api/v1"),
    _provider("jiekou-ai", "Jiekou.AI", "https://api.jiekou.ai/openai/v1"),
    _provider("kilo-gateway", "Kilo Gateway", "https://api.kilo.ai/api/openrouter"),
    _provider(
        "kuae-coding", "KUAE Cloud Coding Plan", "https://coding-plan-endpoint.kuaecloud.net/v1"
    ),
    _provider("llama-gateway", "Llama (LLM Gateway)", "https://api.llama.com/compat/v1"),
    _provider(
        "lmstudio",
        "LMStudio",
        "http://127.0.0.1:1234/v1",
        fallback_models=("qwen3-32b", "deepseek-r1-distill-qwen-32b", "glm-4.5-air"),
    ),
    _provider("lucidquery-ai", "LucidQuery AI", "https://lucidquery.com/api/v1"),
    _provider("meganova", "Meganova", "https://api.meganova.ai/v1"),
    _provider(
        "minimax-io",
        "MiniMax (minimax.io)",
        "https://api.minimax.io/v1",
        fallback_models=_MINIMAX_MODELS,
    ),
    _provider(
        "minimax-cn",
        "MiniMax (minimaxi.com)",
        "https://api.minimaxi.com/v1",
        fallback_models=_MINIMAX_MODELS,
    ),
    _provider(
        "minimax-coding-io",
        "MiniMax Coding Plan (minimax.io)",
        "https://api.minimax.io/coding/v1",
        fallback_models=_MINIMAX_MODELS,
    ),
    _provider(
        "minimax-coding-cn",
        "MiniMax Coding Plan (minimaxi.com)",
        "https://api.minimaxi.com/coding/v1",
        fallback_models=_MINIMAX_MODELS,
    ),
    _provider(
        "mistral",
        "Mistral",
        "https://api.mistral.ai/v1",
        fallback_models=_MISTRAL_MODELS,
    ),
    _provider("mixlayer", "Mixlayer", "https://models.mixlayer.ai/v1"),
    _provider("moark", "Moark", "https://api.moark.com/v1"),
    _provider(
        "modelscope",
        "ModelScope",
        "https://api-inference.modelscope.cn/v1",
        fallback_models=_QWEN_MODELS,
    ),
    _provider(
        "moonshot-ai",
        "Moonshot AI",
        "https://api.moonshot.ai/v1",
        fallback_models=_KIMI_MODELS,
    ),
    _provider(
        "moonshot-ai-cn",
        "Moonshot AI (China)",
        "https://api.moonshot.cn/v1",
        fallback_models=_KIMI_MODELS,
    ),
    _provider(
        "morph",
        "Morph",
        "https://api.morphllm.com/v1",
        fallback_models=("morph-v3-large", "morph-v3-fast"),
    ),
    _provider("nanogpt", "NanoGPT", "https://nano-gpt.com/api/v1"),
    _provider(
        "nebius-token-factory",
        "Nebius Token Factory",
        "https://api.studio.nebius.com/v1",
    ),
    _provider(
        "nova",
        "Nova",
        "https://api.nova.amazon.com/v1",
        fallback_models=("nova-pro-v1", "nova-lite-v1", "nova-premier-v1"),
    ),
    _provider("novita-ai", "NovitaAI", "https://api.novita.ai/v3/openai"),
    _provider(
        "nvidia",
        "Nvidia",
        "https://integrate.api.nvidia.com/v1",
        fallback_models=(
            "nvidia/llama-3.3-nemotron-ultra-253b-v1",
            "deepseek-ai/deepseek-r1",
            "qwen/qwen3-235b-a22b",
        ),
    ),
    _provider("ollama-cloud", "Ollama Cloud", "https://ollama.com/v1"),
    _provider("opencode-zen", "OpenCode Zen", "https://opencode.ai/zen/v1"),
    _provider(
        "openrouter",
        "OpenRouter",
        "https://openrouter.ai/api/v1",
        fallback_models=_OPENROUTER_MODELS,
    ),
    _provider(
        "ovhcloud", "OVHcloud AI Endpoints", "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"
    ),
    _provider(
        "perplexity",
        "Perplexity",
        "https://api.perplexity.ai",
        fallback_models=(
            "sonar-reasoning-pro",
            "sonar-deep-research",
            "sonar-pro",
            "r1-1776",
        ),
    ),
    _provider("poe", "Poe", "https://api.poe.com/v1"),
    _provider("privatemode-ai", "Privatemode AI", "https://api.privatemode.ai/v1"),
    _provider("qihang", "QiHang", "https://api.qihang.ai/v1"),
    _provider("qiniu", "Qiniu", "https://api.qnaigc.com/v1"),
    _provider("regolo-ai", "Regolo AI", "https://api.regolo.ai/v1"),
    _provider("requesty", "Requesty", "https://router.requesty.ai/v1"),
    _provider("sap-ai-core", "SAP AI Core", None, route="litellm"),
    _provider("scaleway", "Scaleway", "https://api.scaleway.ai/v1"),
    _provider("siliconflow", "SiliconFlow", "https://api.siliconflow.com/v1"),
    _provider("siliconflow-cn", "SiliconFlow (China)", "https://api.siliconflow.cn/v1"),
    _provider(
        "stackit", "STACKIT", "https://api.openai-compat.model-serving.eu01.onstackit.cloud/v1"
    ),
    _provider(
        "stepfun",
        "StepFun",
        "https://api.stepfun.com/v1",
        fallback_models=("step-r1-v-mini", "step-2-16k", "step-1-256k"),
    ),
    _provider("submodel", "submodel", "https://llm.submodel.ai/v1"),
    _provider("synthetic", "Synthetic", "https://api.synthetic.new/openai/v1"),
    _provider(
        "tencent-coding-cn",
        "Tencent Coding Plan (China)",
        "https://api.lkeap.cloud.tencent.com/coding/v1",
    ),
    _provider(
        "tencent-tokenhub",
        "Tencent TokenHub",
        "https://api.lkeap.cloud.tencent.com/v1",
    ),
    _provider("the-grid-ai", "The Grid AI", "https://api.thegrid.ai/v1"),
    _provider("together-ai", "Together AI", "https://api.together.xyz/v1"),
    _provider(
        "upstage",
        "Upstage",
        "https://api.upstage.ai/v1/solar",
        fallback_models=("solar-pro2", "solar-pro", "solar-mini"),
    ),
    _provider("v0", "v0", "https://api.v0.dev/v1", fallback_models=("v0-1.5-lg", "v0-1.5-md")),
    _provider("vercel-ai-gateway", "Vercel AI Gateway", "https://ai-gateway.vercel.sh/v1"),
    _provider(
        "vertex",
        "Vertex",
        None,
        route="litellm",
        fallback_models=("vertex_ai/gemini-2.5-pro", "vertex_ai/gemini-2.5-flash"),
    ),
    _provider(
        "vertex-anthropic",
        "Vertex (Anthropic)",
        None,
        route="litellm",
        fallback_models=("vertex_ai/claude-opus-4-7", "vertex_ai/claude-sonnet-4-6"),
    ),
    _provider("vivgrid", "Vivgrid", "https://api.vivgrid.com/v1"),
    _provider("vultr", "Vultr", "https://api.vultrinference.com/v1"),
    _provider("wafer", "Wafer", "https://api.wafer.ai/v1"),
    _provider("wandb", "Weights & Biases", "https://api.inference.wandb.ai/v1"),
    _provider("zenmux", "ZenMux", "https://zenmux.ai/api/v1"),
    _provider(
        "zhipu-ai",
        "Zhipu AI",
        "https://open.bigmodel.cn/api/paas/v4",
        fallback_models=_ZAI_MODELS,
    ),
    _provider(
        "zhipu-ai-coding",
        "Zhipu AI Coding Plan",
        "https://open.bigmodel.cn/api/coding/paas/v4",
        fallback_models=_ZAI_MODELS,
    ),
)


def catalog_payload() -> dict[str, Any]:
    return {
        "title": "Select model",
        "sections": [
            {
                "title": "Recommended",
                "entries": [entry.public() for entry in RECOMMENDED],
            },
            {
                "title": "Other models",
                "entries": [entry.public() for entry in OTHER],
            },
        ],
    }


def find_entry(entry_id: str) -> CatalogEntry | None:
    """The leaf or group with this id, searched depth-first."""
    for entry in (*RECOMMENDED, *OTHER):
        found = _find(entry, entry_id)
        if found is not None:
            return found
    return None


def _find(entry: CatalogEntry, entry_id: str) -> CatalogEntry | None:
    if entry.id == entry_id:
        return entry
    for child in entry.children:
        found = _find(child, entry_id)
        if found is not None:
            return found
    return None


def format_model_setting(route: Route, model_id: str) -> str:
    """The ``REDJOHN_LLM`` value for a model chosen from ``route``."""
    model_id = model_id.strip().strip("/")
    if not model_id:
        raise ValueError("model id is empty")
    if route == "chatgpt":
        slug = model_id.removeprefix("chatgpt/")
        return f"chatgpt/{slug}"
    if route == "grok":
        slug = model_id.removeprefix("grok/")
        return f"grok/{slug}"
    if route == "anthropic":
        slug = model_id.removeprefix("anthropic/")
        return f"anthropic/{slug}"
    if route == "xai":
        slug = model_id.removeprefix("xai/")
        return f"xai/{slug}"
    if route == "litellm":
        return model_id
    slug = model_id.removeprefix("openai/")
    return f"openai/{slug}"


def connection_clears_base(entry: CatalogEntry) -> bool:
    """Official and subscription routes must not keep a previous gateway URL."""
    if entry.route in {"chatgpt", "grok", "anthropic", "xai", "litellm"}:
        return True
    return entry.id == "openai.api-key"


def list_models(entry: CatalogEntry, api_key: str | None) -> tuple[list[dict[str, Any]], str]:
    """Return ``(models, source)`` where source is ``live`` or ``fallback``."""
    if entry.api_base and api_key:
        try:
            live = fetch_model_list(entry, api_key)
        except requests.RequestException:
            live = []
        except ValueError:
            live = []
        if live:
            return live, "live"
    # The fallback list carries the same effort metadata a live list would,
    # resolved exactly as the picker will resolve the chosen model (through
    # the entry's route), so both sources render identical effort modes.
    fallback: list[dict[str, Any]] = []
    for model_id in entry.fallback_models:
        item: dict[str, Any] = {"id": model_id, "label": model_id}
        spec = resolve_model_effort_spec(format_model_setting(entry.route, model_id))
        if spec.supported_efforts:
            item["default_effort"] = spec.default_effort
            item["supported_efforts"] = list(spec.supported_efforts)
        fallback.append(item)
    if not fallback:
        raise ValueError(f"{entry.label} did not return a model list. Check the key and try again.")
    return fallback, "fallback"


def fetch_model_list(entry: CatalogEntry, api_key: str) -> list[dict[str, str]]:
    """GET the provider's model list. Raises when the call itself fails."""
    if not entry.api_base:
        return []
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    if entry.route == "anthropic":
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Accept": "application/json",
        }
    response = requests.get(
        entry.api_base.rstrip("/") + "/models",
        headers=headers,
        timeout=_FETCH_TIMEOUT,
    )
    if response.status_code >= 400:
        raise ValueError(f"HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("model list was not JSON") from exc
    return models_from_payload(payload)


_DYNAMIC_EFFORT_SPECS: dict[str, ModelEffortSpec] = {}
_DYNAMIC_MODEL_LABELS: dict[str, str] = {}


def _extract_effort_spec(row: dict[str, Any]) -> ModelEffortSpec | None:
    effort_raw = row.get("effort") or row.get("reasoning_effort") or row.get("reasoning")
    if not isinstance(effort_raw, dict):
        return None
    raw_levels = (
        effort_raw.get("supported_levels")
        or effort_raw.get("supported_efforts")
        or effort_raw.get("levels")
    )
    if not isinstance(raw_levels, list):
        return None
    levels = tuple(
        str(item).strip().lower()
        for item in raw_levels
        if isinstance(item, str) and str(item).strip().lower() in EFFORTS
    )
    if not levels:
        return None
    raw_default = (
        effort_raw.get("default_level")
        or effort_raw.get("default_effort")
        or effort_raw.get("default")
    )
    default_level = (
        str(raw_default).strip().lower()
        if isinstance(raw_default, str) and str(raw_default).strip().lower() in levels
        else ("high" if "high" in levels else levels[-1])
    )
    supports_reasoning = any(lvl != "none" for lvl in levels)
    return ModelEffortSpec(
        default_effort=default_level,
        supported_efforts=levels,
        supports_reasoning=supports_reasoning,
    )


def register_dynamic_model_metadata(
    model_id: str,
    *,
    label: str | None = None,
    spec: ModelEffortSpec | None = None,
) -> None:
    raw = model_id.strip().lower()
    if not raw:
        return
    slug = raw.rsplit("/", 1)[-1]
    if spec is not None:
        _DYNAMIC_EFFORT_SPECS[raw] = spec
        _DYNAMIC_EFFORT_SPECS[slug] = spec
    if isinstance(label, str) and label.strip():
        clean_label = label.strip()
        _DYNAMIC_MODEL_LABELS[raw] = clean_label
        _DYNAMIC_MODEL_LABELS[slug] = clean_label


def models_from_payload(payload: object) -> list[dict[str, Any]]:
    """Normalize an OpenAI- or Anthropic-shaped model list, preserving effort capabilities."""
    rows: list[object]
    if isinstance(payload, dict):
        data = payload.get("data", payload.get("models"))
        rows = data if isinstance(data, list) else []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        spec: ModelEffortSpec | None = None
        if isinstance(row, str):
            model_id, label = row, row
        elif isinstance(row, dict):
            raw_id = row.get("id") or row.get("name")
            if not isinstance(raw_id, str) or not raw_id.strip():
                continue
            model_id = raw_id.strip()
            raw_label = row.get("display_name") or row.get("name") or model_id
            label = model_id
            if isinstance(raw_label, str) and raw_label.strip():
                label = raw_label.strip()
            spec = _extract_effort_spec(row)
            register_dynamic_model_metadata(model_id, label=label, spec=spec)
        else:
            continue
        if _skips_model(model_id) or model_id in seen:
            continue
        seen.add(model_id)
        item: dict[str, Any] = {"id": model_id, "label": label}
        if spec is not None:
            item["default_effort"] = spec.default_effort
            item["supported_efforts"] = list(spec.supported_efforts)
        models.append(item)
        if len(models) >= _MAX_MODELS:
            break
    models.sort(key=lambda entry: str(entry["label"]).casefold())
    return models


def _skips_model(model_id: str) -> bool:
    lowered = model_id.lower()
    return any(marker in lowered for marker in _NON_CHAT_MARKERS)


_NON_REASONING_MARKERS = (
    "gpt-4o",
    "gpt-4.1",
    "gpt-4-turbo",
    "gpt-3.5",
    "claude-3-5-haiku",
    "claude-3-haiku",
    "mimo-v2-flash",
    "mimo-v2.6-flash",
    "grok-4-fast",
    "grok-code-fast",
    "glm-4-flash",
    "qwen-turbo",
    "mistral-small",
    "ministral",
    "command-r",
    "mercury-coder",
    "morph-v3-fast",
    "solar-mini",
    # Instruct/completion lines without a thinking mode.
    "moonshot-v1",
    "kimi-k2-instruct",
    "llama-3",
    "codestral",
    # Perplexity's non-reasoning sonar (does not match sonar-reasoning-*).
    "sonar-pro",
    # Pre-thinking Gemini line (2.5/3 stay reasoning).
    "gemini-2.0",
)


def resolve_model_effort_spec(model_name: str | None) -> ModelEffortSpec:  # noqa: PLR0911
    """Return the default reasoning effort and supported effort levels for ``model_name``.

    When no model is configured (empty or ``None``), returns an empty spec so the
    TUI does not display a misleading default effort before a model is chosen.
    """
    raw = (model_name or "").strip()
    if not raw:
        return ModelEffortSpec(default_effort="", supported_efforts=(), supports_reasoning=False)

    lowered = raw.lower()
    route_prefix, _, tail = lowered.partition("/")
    slug = tail or route_prefix
    if "/" in slug:
        slug = slug.rsplit("/", 1)[-1]

    if lowered in _DYNAMIC_EFFORT_SPECS:
        return _DYNAMIC_EFFORT_SPECS[lowered]
    if slug in _DYNAMIC_EFFORT_SPECS:
        return _DYNAMIC_EFFORT_SPECS[slug]

    try:
        from redjohn.config.loader import load_settings

        llm = load_settings().llm
        cfg_model = (llm.model or "").strip().lower()
        cfg_slug = cfg_model.rsplit("/", 1)[-1] if cfg_model else ""
        if llm.supported_efforts and (lowered == cfg_model or slug == cfg_slug):
            levels = tuple(lvl for lvl in llm.supported_efforts if lvl in EFFORTS)
            if levels:
                default_eff = (
                    llm.reasoning_effort
                    if llm.reasoning_effort in levels
                    else ("high" if "high" in levels else levels[-1])
                )
                return ModelEffortSpec(
                    default_effort=default_eff,
                    supported_efforts=levels,
                    supports_reasoning=any(lvl != "none" for lvl in levels),
                )
    except Exception:  # noqa: BLE001
        pass

    if any(marker in slug for marker in ("deepseek-v4", "deepseek-flash")):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("low", "high", "max"),
            supports_reasoning=True,
        )

    # Nemotron Ultra is a reasoning-capable Llama derivative; this must run
    # before the plain "llama-3" non-reasoning marker so it is not caught.
    if "nemotron" in slug:
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "low", "medium", "high"),
            supports_reasoning=True,
        )

    if any(marker in slug for marker in _NON_REASONING_MARKERS):
        return ModelEffortSpec(
            default_effort="none",
            supported_efforts=("none",),
            supports_reasoning=False,
        )

    if slug in {"deepseek-chat", "deepseek-v3"} and "r1" not in slug and "reasoner" not in slug:
        return ModelEffortSpec(
            default_effort="none",
            supported_efforts=("none",),
            supports_reasoning=False,
        )

    if route_prefix == "chatgpt":
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "low", "medium", "high"),
            supports_reasoning=True,
        )

    if any(
        slug.startswith(prefix) or f"-{prefix}" in slug
        for prefix in ("gpt-5", "o1", "o3", "o4", "codex")
    ):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "minimal", "low", "medium", "high", "xhigh"),
            supports_reasoning=True,
        )

    if any(
        marker in slug
        for marker in (
            "claude-opus-4",
            "claude-sonnet-4",
            "claude-haiku-4",
            "claude-3-7",
            "opus-4",
            "sonnet-4",
        )
    ):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "low", "medium", "high", "max"),
            supports_reasoning=True,
        )

    if any(
        marker in slug
        for marker in (
            "deepseek-r1",
            "deepseek-reasoner",
            "qwq",
            "r1-1776",
            "step-r1",
            "sonar-reasoning",
        )
    ):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("low", "medium", "high", "max"),
            supports_reasoning=True,
        )

    if any(marker in slug for marker in ("gemini-2.5", "gemini-3")):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "minimal", "low", "medium", "high"),
            supports_reasoning=True,
        )

    if any(
        marker in slug
        for marker in (
            "qwen3",
            "qwen-3",
            "qwen-max",
            "glm-5",
            "glm5",
            "glm-4.6",
            "glm-4.5",
            "kimi-k2",
            "kimi-for-coding",
            "mimo-v2-pro",
            "mimo-v2.5",
            "mimo-v2.6-pro",
            "minimax-m1",
            "minimax-m2",
            "grok-4",
            "grok-3",
            "magistral",
        )
    ):
        return ModelEffortSpec(
            default_effort="high",
            supported_efforts=("none", "low", "medium", "high"),
            supports_reasoning=True,
        )

    return ModelEffortSpec(
        default_effort="high",
        supported_efforts=("none", "low", "medium", "high"),
        supports_reasoning=True,
    )


def short_model_label(model_name: str | None) -> str:  # noqa: PLR0911
    """Return a compact display name (e.g. ``Qwen3``, ``GLM5.3``) for the TUI stats box."""
    raw = (model_name or "").strip()
    if not raw:
        return "not set"
    lowered = raw.lower()
    slug = raw.rsplit("/", 1)[-1].strip()
    lower = slug.lower()

    if lowered in _DYNAMIC_MODEL_LABELS:
        dyn = _DYNAMIC_MODEL_LABELS[lowered]
        if len(dyn) <= 22:
            return dyn
    if lower in _DYNAMIC_MODEL_LABELS:
        dyn = _DYNAMIC_MODEL_LABELS[lower]
        if len(dyn) <= 22:
            return dyn

    try:
        from redjohn.config.loader import load_settings

        llm = load_settings().llm
        cfg_model = (llm.model or "").strip().lower()
        cfg_slug = cfg_model.rsplit("/", 1)[-1] if cfg_model else ""
        if llm.model_label and (lowered == cfg_model or lower == cfg_slug):
            if len(llm.model_label) <= 22:
                return llm.model_label
    except Exception:  # noqa: BLE001
        pass

    if lower == "deepseek-flash" or "deepseek-v4.1-flash" in lower:
        return "DeepSeek-V4.1-Flash"
    if "deepseek-v4-pro" in lower:
        return "DeepSeek-V4-Pro"
    if "qwen3" in lower or "qwen-3" in lower:
        if "coder" in lower:
            return "Qwen3 Coder"
        return "Qwen3"
    if "qwq" in lower:
        return "QwQ"
    glm_match = re.search(r"glm[-_]?(\d+(?:\.\d+)?)", lower)
    if glm_match:
        return f"GLM{glm_match.group(1)}"
    if "claude" in lower:
        if "opus-4-7" in lower or "opus-4.7" in lower:
            return "Opus 4.7"
        if "sonnet-4-6" in lower or "sonnet-4.6" in lower:
            return "Sonnet 4.6"
        if "haiku-4-5" in lower or "haiku-4.5" in lower:
            return "Haiku 4.5"
        if "opus" in lower:
            return "Claude Opus"
        if "sonnet" in lower:
            return "Claude Sonnet"
        if "haiku" in lower:
            return "Claude Haiku"
        return "Claude"
    gpt_match = re.search(r"gpt[-_]?(\d+(?:\.\d+)?(?:-codex|-mini)?)", lower)
    if gpt_match:
        tag = gpt_match.group(1).upper()
        return f"GPT-{tag}"
    if lower.startswith(("o1", "o3", "o4")):
        return slug.upper()
    if "deepseek-r1" in lower or "deepseek-reasoner" in lower:
        return "DeepSeek R1"
    if "deepseek-v3" in lower or "deepseek-chat" in lower:
        return "DeepSeek V3"
    if "kimi-k2" in lower:
        return "Kimi K2"
    if "kimi" in lower:
        return "Kimi"
    mimo_match = re.search(r"mimo[-_]?v?(\d+(?:\.\d+)?)", lower)
    if mimo_match:
        return f"MiMo v{mimo_match.group(1)}"
    grok_match = re.search(r"grok[-_]?(\d+)", lower)
    if grok_match:
        return f"Grok {grok_match.group(1)}"
    gemini_match = re.search(r"gemini[-_]?(\d+(?:\.\d+)?)", lower)
    if gemini_match:
        return f"Gemini {gemini_match.group(1)}"
    if "minimax-m2" in lower:
        return "MiniMax M2"
    if "minimax-m1" in lower:
        return "MiniMax M1"
    if len(slug) > 16:
        return slug[:15] + "…"
    return slug
