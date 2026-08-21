# Sleuth × Needle 2

Fine-tune [Needle 2](https://github.com/cactus-compute/needle) (45M-param tool
router, ~14MB) so Sleuth does not need a large uncensored chat model just to
call tools.

## What “uncensored” means here

Needle does not chat. It only emits tool calls. The LoRA dataset trains it to:

1. Route authorised recon / APK / vuln-research prompts to Sleuth tools
2. **Never refuse** those calls with policy text
3. Return `answers: []` on small talk so it does not spam tools

## Train

```bash
pip install -r requirements.txt
chmod +x train.sh serve.sh
./train.sh
```

Artifacts:

| Path | Role |
|------|------|
| `data/sleuth_needle.jsonl` | Training set |
| `checkpoints/sleuth_needle_lora.pkl` | LoRA adapter |
| `dist/sleuth_needle.cact` | Merged runnable weights |

Env knobs: `EPOCHS`, `BATCH`, `LR`, `RANK`, `MAXLEN`.

## Serve + point Sleuth at it

```bash
./serve.sh
```

```env
LLM_PROVIDER=custom
LLM_BASE_URL=http://host.docker.internal:8000/v1
LLM_MODEL=sleuth-needle
```

## Limits

- Needle will not write long essays; Sleuth should answer from tool output.
- Active scan tools remain gated by Sleuth `.env` flags (`ZAP_ALLOW_ACTIVE_SCAN`, etc.).
- Use only on targets you own or are authorised to test.
