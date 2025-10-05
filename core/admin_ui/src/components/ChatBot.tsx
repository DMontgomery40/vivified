import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, TextField, Button, Divider, Alert, FormControlLabel, Switch, Tooltip } from '@mui/material';
import AdminAPIClient from '../api/client';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  tools_used?: Array<{ name?: string; args?: any; content?: string }>;
}

export default function ChatBot({ client }: { client: AdminAPIClient }) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('Hello!');
  const [busy, setBusy] = useState(false);
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [cfgMsg, setCfgMsg] = useState<string>('');
  const [hipaaMode, setHipaaMode] = useState<boolean>(true);

  useEffect(() => {
    (async () => {
      try {
        const cfg = await client.getAiConfig();
        const hasKey = Boolean(cfg?.llm?.api_key_present);
        setConfigured(hasKey);
        setCfgMsg(hasKey ? '' : 'LOCAL ONLY: Set Provider + API key in AI Studio → Connectors, then return to Chat.');
      } catch {
        setConfigured(false);
        setCfgMsg('Unable to load AI config.');
      }
    })();
  }, [client]);

  const send = async () => {
    if (!input.trim()) return;
    const userMsg: ChatMessage = { role: 'user', content: input.trim() };
    const conversationHistory = [...messages, userMsg];
    setMessages(conversationHistory);
    setInput('');
    try {
      setBusy(true);
      // Send the FULL conversation history, not just the latest message
      const res = await client.aiAgentRun(conversationHistory, hipaaMode);
      const asst: ChatMessage = {
        role: 'assistant',
        content: (res as any)?.result || '',
        tools_used: (res as any)?.tools_used || [],
      };
      setMessages((m) => [...m, asst]);
    } catch (e: any) {
      const err: ChatMessage = { role: 'assistant', content: e?.message || 'Agent failed' };
      setMessages((m) => [...m, err]);
    } finally { setBusy(false); }
  };

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Typography variant="h4">Chat</Typography>
        <Tooltip title={hipaaMode ? "HIPAA mode ON: Generated code will include HIPAA compliance fields (hipaa_controls, handles_phi, audit_level). Turn OFF for non-healthcare projects." : "HIPAA mode OFF: Generated code will NOT include healthcare compliance fields. Turn ON if building for healthcare/PHI."}>
          <FormControlLabel
            control={<Switch checked={hipaaMode} onChange={(e) => setHipaaMode(e.target.checked)} />}
            label={<Typography variant="body2">HIPAA Mode</Typography>}
          />
        </Tooltip>
      </Stack>
      {configured === false && (
        <Alert severity="warning" sx={{ mb: 2 }}>{cfgMsg}</Alert>
      )}
      {!hipaaMode && (
        <Alert severity="info" sx={{ mb: 2 }}>
          HIPAA mode is <strong>OFF</strong>. Generated code will exclude healthcare compliance fields (hipaa_controls, handles_phi, data_classification).
        </Alert>
      )}
      <Paper sx={{ p: 2, borderRadius: 2, mb: 2, minHeight: 240 }}>
        {(messages.length === 0) && (
          <Typography variant="body2" color="text.secondary">Start the conversation. Tool-calling is used when enabled in AI Studio Connectors.</Typography>
        )}
        {messages.map((m, i) => (
          <Box key={i} sx={{ mb: 2 }}>
            <Typography variant="subtitle2" color={m.role === 'user' ? 'primary' : 'secondary'}>{m.role === 'user' ? 'You' : 'Assistant'}</Typography>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{m.content}</Typography>
            {m.tools_used && m.tools_used.length > 0 && (
              <Box sx={{ mt: 1, ml: 1 }}>
                <Typography variant="caption" color="text.secondary">Tools used:</Typography>
                {m.tools_used.map((t, idx) => (
                  <Typography key={idx} variant="caption" sx={{ display: 'block' }}>• {t.name || 'tool'} {t.args ? `(${JSON.stringify(t.args)})` : ''}</Typography>
                ))}
              </Box>
            )}
            <Divider sx={{ my: 1 }} />
          </Box>
        ))}
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          <TextField fullWidth value={input} onChange={(e) => setInput(e.target.value)} placeholder="Type a message" />
          <Button variant="contained" onClick={send} disabled={busy} sx={{ borderRadius: 2 }}>{busy ? 'Sending…' : 'Send'}</Button>
        </Stack>
      </Paper>
    </Box>
  );
}
