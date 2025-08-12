const categories = [
  { id: 'information_leakage', description: 'Exposure of sensitive data via the surface.' },
  { id: 'data_integrity_violation', description: 'Unauthorized modification/destruction of data.' },
  { id: 'control_plane_subversion', description: 'Unauthorized modification/execution on the control plane.' },
  { id: 'denial_of_service', description: 'Degradation or loss of availability.' },
  { id: 'illegitimate_use', description: 'Abuse/misuse of resources beyond intended purpose.' },
  { id: 'entity_spoofing', description: 'Masquerading as another principal/service.' },
  { id: 'forgery', description: 'Fabricating messages/requests accepted as if from a trusted source.' },
  { id: 'bypassing_control', description: 'Circumventing security controls (filtering, validation, authN/Z gates).' },
  { id: 'authorization_violation', description: 'Access beyond assigned permissions.' },
  { id: 'trojan', description: 'Malicious/compromised components introduced via supply chain or artifact.' },
  { id: 'guessing', description: 'Ability to deduce or predict sensitive values (e.g., keys, tokens, identifiers).' },
  { id: 'repudiation', description: 'Denying actions/transactions due to insufficient auditability or tamper-proof logging.' }
];

const table = document.getElementById('attack-table');
const addRowBtn = document.getElementById('add-row');
const submitBtn = document.getElementById('submit-ai');
const errorDiv = document.getElementById('error');

addRowBtn.addEventListener('click', () => {
  const row = table.tBodies[0].insertRow();
  row.insertCell().setAttribute('contenteditable', 'true');
  row.insertCell().setAttribute('contenteditable', 'true');
  if (table.tHead.rows[0].cells.length > 2) {
    row.insertCell();
    row.insertCell();
  }
});

submitBtn.addEventListener('click', async () => {
  errorDiv.textContent = '';
  const apiKey = document.getElementById('api-key').value.trim();
  if (!apiKey) {
    errorDiv.textContent = 'API key required.';
    return;
  }
  const rows = Array.from(table.tBodies[0].rows).map((tr, idx) => ({
    index: idx,
    surface: tr.cells[0].innerText.trim(),
    description: tr.cells[1].innerText.trim()
  }));
  const prompt = `
You are a threat modeling assistant. For each attack surface below, identify applicable threat categories from this list and provide a brief description. Omit categories that do not apply. Respond with JSON only in the form:
[
  {"index":0,"threats":[{"type":"<category_id>","description":"<text>"}]}
]

Threat Categories:
${categories.map(c => c.id + ': ' + c.description).join('\n')}

Attack Surfaces:
${rows.map(r => `#${r.index}: ${r.surface} - ${r.description}`).join('\n')}
`;

  try {
    const res = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        input: prompt,
        response_format: { type: 'json_object' }
      })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error?.message || 'Request failed');
    }
    let parsed;
    try {
      parsed = JSON.parse(data.output[0].content[0].text);
    } catch (e) {
      throw new Error('Failed to parse AI response.');
    }

    const headRow = table.tHead.rows[0];
    if (headRow.cells.length === 2) {
      headRow.insertCell(2).innerText = 'Threat Type';
      headRow.insertCell(3).innerText = 'Threat Description';
      Array.from(table.tBodies[0].rows).forEach(tr => {
        tr.insertCell(2);
        tr.insertCell(3);
      });
    }

    parsed.forEach(item => {
      const tr = table.tBodies[0].rows[item.index];
      const types = item.threats.map(t => t.type).join('\n');
      const descs = item.threats.map(t => t.description).join('\n');
      tr.cells[2].innerText = types;
      tr.cells[3].innerText = descs;
    });
  } catch (err) {
    errorDiv.textContent = err.message;
  }
});
