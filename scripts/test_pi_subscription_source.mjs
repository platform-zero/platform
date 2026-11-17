// Offline provider boundary. Never reads a real OAuth credential or calls an upstream.
import assert from 'node:assert/strict';
import { translate, responseFromPi } from '../src/main/resources/runtime/pi_subscription_broker.mjs';
const input={model:'gpt-6-sol',stream:true,store:false,reasoning:{effort:'medium'},
  input:[{role:'developer',content:[{type:'input_text',text:'test'}]},
    {role:'user',content:[{type:'input_text',text:'hello'}]},
    {type:'configuration_update',reasoning:{effort:'high'}}],
  tools:[{type:'function',name:'read',description:'read',parameters:{type:'object',properties:{path:{type:'string'}}}}]};
const result=translate(input);
assert.deepEqual(result.context.messages.map(x=>x.role),['user']);
assert.equal(result.context.systemPrompt,'test');
assert.equal(result.context.tools[0].name,'read');
assert.equal(result.options.reasoning,'high');
assert.throws(()=>translate({...input,model:'openrouter/unknown'}));
assert.throws(()=>translate({...input,input:[{type:'unsupported'}]}));
const withTool={...input,input:[input.input[1],
  {type:'function_call',id:'fc_test',call_id:'call_123',name:'read',arguments:'{"path":"/tmp/test"}'},
  {type:'function_call_output',call_id:'call_123',output:'ok'}]};
assert.deepEqual(translate(withTool).context.messages.map(x=>x.role),['user','assistant','toolResult']);
const response=responseFromPi({role:'assistant',provider:'openai',model:'gpt-6-sol',stopReason:'toolUse',
  content:[{type:'toolCall',id:'call_123|fc_test',name:'read',arguments:{path:'/tmp/test'}}],
  usage:{input:5,output:4,totalTokens:9}});
assert.equal(response.output[0].type,'function_call');
assert.equal(response.output[0].call_id,'call_123');
// Capture an actual installed Pi openai-responses request against a localhost
// synthetic provider, including its configuration_update and tool definitions.
import http from 'node:http';
import { ModelRuntime } from '/home/gerald/.local/share/pi/lib/node_modules/@earendil-works/pi-coding-agent/dist/index.js';
import { stream } from '/home/gerald/.local/share/pi/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/api/openai-responses.js';
import { normalizeContext } from '/home/gerald/.local/share/pi/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/utils/transcript.js';
let observed;
const item={id:'msg_pi_fixture',type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'fixture',annotations:[]}]};
const completed={id:'resp_pi_fixture',object:'response',status:'completed',model:'gpt-6-sol',output:[item],usage:{input_tokens:1,output_tokens:1,total_tokens:2}};
const event=(type,more={})=>`data: ${JSON.stringify({type,...more})}\n\n`;
const events=event('response.created',{response:completed})+event('response.output_item.added',{output_index:0,item})+
  event('response.output_item.done',{output_index:0,item})+event('response.completed',{response:completed})+'data: [DONE]\n\n';
const server=http.createServer(async(req,res)=>{
  let bytes='';for await(const chunk of req)bytes+=chunk;
  const candidate=JSON.parse(bytes);
  try { observed=translate(candidate); } catch (error) {
    console.error(JSON.stringify({error:error.message,inputKinds:candidate.input?.map(x=>x.type??x.role),toolShapes:candidate.input?.filter(x=>x.type==='additional_tools').map(x=>({role:x.role,defs:x.tools?.map(t=>({type:t.type,name:t.name,paramsType:typeof t.parameters}))}))}));
    observed=null;
  }
  res.writeHead(200,{'Content-Type':'text/event-stream'});res.end(events);
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try {
  const runtime=await ModelRuntime.create({authPath:'/tmp/nonexistent-pi-fixture-auth',modelsPath:'/tmp/nonexistent-pi-fixture-models'});
  const model={...runtime.getModel('openai','gpt-6-sol'),baseUrl:`http://127.0.0.1:${server.address().port}/v1`};
  const native=await stream(model,normalizeContext({systemPrompt:'system',messages:[{role:'user',content:[{type:'text',text:'hello'}],timestamp:Date.now()}],
    tools:[{name:'read',description:'read',parameters:{type:'object',properties:{path:{type:'string'}}}}]}),
    {apiKey:'synthetic-fixture-not-real-oauth',reasoningEffort:'medium'}).result();
  assert.equal(native.content.find(x=>x.type==='text')?.text,'fixture');
  assert.equal(observed.context.messages.at(-1).role,'user');
  assert.equal(observed.context.tools[0].name,'read');
  assert.equal(observed.options.reasoning,'medium');
} finally { server.close(); }
console.log('Pi subscription source mapping and installed Responses parser passed; no real OAuth request');
