You are a senior backend architect and expert in agent frameworks. Refactor my existing Python agent codebase to implement a production-grade multi-model pairing system using a registry-driven approach. Do NOT create a new project. Integrate everything into the existing codebase cleanly.

Objective:
Implement a model pairing (multi-model routing + resilience layer) that:
- Supports multiple LLMs (GPT, Gemini, Llama, etc.)
- Routes requests dynamically using strategies (round-robin, priority)
- Handles retries, failover, and cooldown
- Maintains sticky sessions for conversational consistency
- Allows per-model and group-level prompt control

Step 1: Project Structure (Integrate, don’t recreate)
Ensure the following structure exists inside my current project:
- llm_config/registry.yml → central config
- .env → environment variables
- agent/my_agent.py → main agent logic
- agent/__init__.py → entrypoint
Do NOT duplicate logic already present. Extend existing modules.

Step 2: Environment Configuration
Add support for environment-driven config:
- MODEL_PAIRING_ENABLED=true
- ROUTER_SESSION_STORAGE_TYPE=memory (dev) / redis (prod)
- GPT4_MODEL=gpt-4o-mini
- GEMINI_MODEL=gemini-2.0-flash-001

Ensure all values in registry.yml can reference env variables like:
${ENV_VAR_NAME}

Step 3: Registry Configuration (Core of system)
Create or refactor registry.yml with:

model_pairing:
  enabled: true

system_prompts:
  - id: support_prompt
    content: |
      You are a helpful assistant. Provide detailed and structured answers.

  - id: concise_prompt
    content: |
      You are a concise assistant. Respond in max 3 sentences.

models:
  - id: gpt4
    model_name: ${GPT4_MODEL}
    system_prompt_ref: support_prompt
    parameters:
      temperature: 0.7
      max_tokens: 500

  - id: gemini_flash
    model_name: ${GEMINI_MODEL}
    system_prompt_ref: concise_prompt
    parameters:
      temperature: 0.5
      max_tokens: 500

  - id: llama
    model_name: llama-2
    parameters:
      temperature: 0.7
      max_tokens: 500

model_groups:
  default:
    system_prompt_ref: support_prompt
    models:
      - gpt4
      - gemini_flash
      - llama
    routing_strategy: "priority"

agent_models:
  main_agent:
    model_group: default

Step 4: Routing Logic Implementation
Implement a ModelRouter layer that:
- Picks model based on routing strategy
- Tracks model health
- Applies cooldown for failed models
- Retries transient errors
- Falls back automatically

Required behaviors:
- round-robin → evenly distribute requests
- priority → always pick first healthy model
- retry same model before fallback
- fallback to next model on failure

Step 5: Resilience + Session Handling
Implement:

model_router:
  sticky_session:
    ttl_minutes: 30
    storage:
      type: memory

  resilience:
    global_cooldown_seconds: 30
    max_retries: 2
    exception_handling:
      retryable_exceptions:
        - timeout
        - rate_limit
      immediate_fallback_exceptions:
        - 500
        - 502

Requirements:
- Same session uses same model unless failure
- Failed model enters cooldown
- After cooldown, model becomes available again

Step 6: Agent Code Changes
In my_agent.py:

Extend BaseAgent and override:

def modify_prompt_per_model(self, prompt: str, model_id: str) -> str:
    if "gemini" in model_id:
        return prompt + "\nBe concise."
    elif "gpt" in model_id:
        return prompt + "\nProvide detailed reasoning."
    return prompt

Ensure:
- Prompt is first resolved from registry
- Then dynamically modified per model

Step 7: Strict Validation (Fail Fast)
At startup:
- Validate every model has a system prompt (direct or inherited)
- Validate all model IDs exist
- Validate env variables are resolved
- If anything missing → fail at startup, not runtime

Step 8: Observability (MANDATORY)
Add logging for:
- Selected model per request
- Retry attempts
- Failover events
- Cooldown triggers

Example logs:
- "Routing request to model: gpt4"
- "Model gpt4 failed, retrying..."
- "Failing over to gemini_flash"

Step 9: Execution
Ensure agent starts using:
start_agent(agent_class=MyAgent)

Agent must read registry.yml from project root.

Constraints:
- Do NOT hardcode model logic
- Do NOT bypass registry.yml
- Do NOT assume single model anywhere
- Do NOT silently ignore failures

Final Output Expectation:
System should:
- Dynamically route across multiple models
- Handle failures without crashing
- Maintain session consistency
- Allow easy addition/removal of models via config
- Be production-ready and observable

Implement clean, modular, extensible code.
