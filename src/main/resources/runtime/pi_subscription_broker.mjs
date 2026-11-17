// Pinned host-only Pi provider adapter. Never runs in Worklane. No logging of
// credentials, prompts, provider errors or refresh material.
import { readFileSync } from 'node:fs';
import { ModelRuntime } from '/home/gerald/.local/share/pi/lib/node_modules/@earendil-works/pi-coding-agent/dist/index.js';

const AUTH = '/home/gerald/.local/share/p0-v3-subscription/openai-only/auth.json';
const MODEL = 'gpt-6-sol';
const PROVIDER = 'openai';
const safe = (x) => x && typeof x === 'object' && !Array.isArray(x);
const assert = (v) => { if (!v) throw Error('invalid subscription request'); };
const text = (v, limit = 1048576) => { assert(typeof v === 'string' && v.length <= limit); return v; };
export function translate(request) {
  assert(safe(request) && request.model === MODEL && Array.isArray(request.input));
  assert(request.input.length <= 300 && (request.store === false || request.store === undefined));
  assert(!request.previous_response_id && !request.background && !request.input_audio);
  const toolDefs = request.tools ?? [];
  assert(Array.isArray(toolDefs) && toolDefs.length <= 64);
  const tools = [];
  const addTools = definitions => {
    assert(Array.isArray(definitions) && definitions.length <= 64 && tools.length + definitions.length <= 128);
    for (const t of definitions) {
      assert(safe(t) && t.type === 'function' && /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(t.name));
      assert(safe(t.parameters));
      const value = { name: t.name, description: text(t.description ?? '', 2048), parameters: t.parameters };
      const old = tools.findIndex(existing => existing.name === t.name);
      if (old !== -1) tools.splice(old, 1);
      tools.push(value);
    }
  };
  addTools(toolDefs);
  const names = new Map();
  const messages = [];
  const instructions = [];
  if (request.instructions !== undefined) instructions.push(text(request.instructions));
  let assistant = null;
  const flush = () => { if (assistant?.content.length) messages.push(assistant); assistant = null; };
  const addAssistant = block => { assistant ??= {role:'assistant',content:[],api:'openai-responses',provider:PROVIDER,model:MODEL,stopReason:'stop',timestamp:Date.now(),usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}}; assistant.content.push(block); };
  let selectedEffort;
  for (const item of request.input) {
    assert(safe(item));
    if (item.type === 'additional_tools') {
      assert(item.role === 'developer'); addTools(item.tools);
    } else if (item.type === 'configuration_update') {
      assert(safe(item.reasoning) && ['none','low','medium','high'].includes(item.reasoning.effort));
      selectedEffort = item.reasoning.effort;
    } else if (item.type === 'function_call') {
      const callId = text(item.call_id, 256), name = text(item.name, 64);
      assert(tools.some(t => t.name === name) && item.arguments.length <= 1048576);
      const args = JSON.parse(item.arguments); assert(safe(args));
      names.set(callId, name);
      addAssistant({type:'toolCall',id:`${callId}|${text(item.id ?? 'fc_pi',128)}`,name,arguments:args});
    } else if (item.type === 'function_call_output') {
      flush();
      const id = text(item.call_id,256), name = names.get(id);
      assert(name && typeof item.output === 'string');
      messages.push({role:'toolResult',toolCallId:`${id}|fc_pi`,toolName:name,content:[{type:'text',text:text(item.output)}],isError:false,timestamp:Date.now()});
    } else if (item.type === 'reasoning') {
      assert(typeof item.encrypted_content === 'string' && item.encrypted_content.length <= 1048576);
      addAssistant({type:'thinking',thinking:'',thinkingSignature:JSON.stringify(item)});
    } else if (item.type === 'message' || item.type === undefined && ['system','developer','user','assistant'].includes(item.role)) {
      const role = item.role;
      assert(typeof item.content === 'string' || Array.isArray(item.content) && item.content.length <= 100);
      const blocks = typeof item.content === 'string' ? [text(item.content)] : item.content.map(c => { assert(safe(c) && (c.type === 'input_text' || c.type === 'output_text')); return text(c.text); });
      if (role === 'system' || role === 'developer') { flush(); instructions.push(blocks.join('\n')); }
      else if (role === 'user') { flush(); messages.push({role:'user',content:[{type:'text',text:blocks.join('\n')}],timestamp:Date.now()}); }
      else if (role === 'assistant') { for (const block of blocks) addAssistant({type:'text',text:block}); }
      else throw Error('invalid role');
    } else throw Error('unsupported Responses item');
  }
  flush();
  assert(messages.length > 0 && messages.at(-1).role !== 'assistant');
  const reasoning = selectedEffort ?? request.reasoning?.effort;
  assert(reasoning === undefined || ['none','low','medium','high'].includes(reasoning));
  assert(request.tool_choice === undefined || request.tool_choice === 'auto' || request.tool_choice === 'required');
  return { context:{systemPrompt:instructions.join('\n'),messages,tools}, options:{reasoning:reasoning === 'none' ? 'off' : reasoning ?? 'off',toolChoice:request.tool_choice === 'required' ? 'required' : undefined} };
}
export function responseFromPi(result) {
  assert(safe(result) && result.role === 'assistant' && result.provider === PROVIDER && result.model === MODEL && result.stopReason !== 'error' && result.stopReason !== 'aborted');
  const output = [];
  for (const block of result.content) {
    if (block.type === 'text') output.push({id:`msg_pi_${output.length}`,type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:text(block.text),annotations:[]}]});
    else if (block.type === 'thinking' && block.thinkingSignature) { const value = JSON.parse(block.thinkingSignature); assert(value.type === 'reasoning'); output.push(value); }
    else if (block.type === 'toolCall') { const [call_id] = block.id.split('|'); assert(call_id && safe(block.arguments)); output.push({id:`fc_pi_${output.length}`,type:'function_call',call_id,name:block.name,arguments:JSON.stringify(block.arguments),status:'completed'}); }
    else throw Error('unsupported provider output');
  }
  const usage = result.usage ?? {};
  return {id:result.responseId ?? `resp_pi_${Date.now()}`,object:'response',status:'completed',model:MODEL,output,usage:{input_tokens:(usage.input ?? 0) + (usage.cacheRead ?? 0),output_tokens:usage.output ?? 0,total_tokens:usage.totalTokens ?? 0,input_tokens_details:{cached_tokens:usage.cacheRead ?? 0},output_tokens_details:{reasoning_tokens:usage.reasoning ?? 0}}};
}
if (process.argv[1]?.endsWith('pi_subscription_broker_v3.mjs')) {
  try {
    const raw = readFileSync(0); assert(raw.length > 1 && raw.length <= 1048576);
    const request = JSON.parse(raw.toString('utf8'));
    const {context,options} = translate(request);
    const auth = JSON.parse(readFileSync(AUTH,'utf8'));
    assert(Object.keys(auth).length === 1 && auth.openai?.type === 'oauth');
    const runtime = await ModelRuntime.create({authPath: AUTH, modelsPath:'/home/gerald/.local/share/p0-v3-subscription/openai-only/no-model-overrides.json'});
    assert(runtime.isUsingOAuth(PROVIDER) && runtime.isUsingSubscription(PROVIDER));
    const model = runtime.getModel(PROVIDER,MODEL);
    assert(model?.provider === PROVIDER && model.id === MODEL && model.api === 'openai-responses');
    const result = await runtime.completeSimple(model,context,options);
    const response = responseFromPi(result);
    process.stdout.write(JSON.stringify(response));
  } catch (_) { process.exitCode = 1; }
}
