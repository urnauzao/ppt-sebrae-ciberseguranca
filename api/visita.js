/**
 * Notificação de visita humana na página /perfil.
 *
 * Roda como função serverless na Vercel, e não no navegador, por dois
 * motivos: a URL do webhook não pode ficar exposta no código do site, e
 * parte da filtragem de robô só é possível no servidor, onde ficam os
 * cabeçalhos da requisição.
 *
 * Privacidade: o endereço IP nunca é armazenado nem enviado ao Discord.
 * Ele é usado apenas para derivar um identificador diário, que serve
 * para não notificar a mesma pessoa várias vezes. A notificação leva
 * somente país e região aproximados, origem do acesso e tipo de
 * dispositivo.
 */

const crypto = require('crypto');

const WEBHOOK = process.env.DISCORD_WEBHOOK_VISITAS || '';

// Dedupe em memória. A instância é efêmera, então isso reduz repetição
// sem a pretensão de ser um controle exato.
const vistos = new Map();
const JANELA_MS = 6 * 60 * 60 * 1000;

// Teto de notificações por instância. O endpoint é público: sem isso,
// quem descobrir a rota consegue inundar o canal de avisos.
const TETO_POR_HORA = 30;
let contador = 0;
let inicioContagem = Date.now();

const PADROES_ROBO = /bot|crawl|spider|slurp|headless|phantom|puppeteer|playwright|selenium|curl|wget|python-requests|httpclient|axios|okhttp|java\/|go-http|libwww|scrapy|facebookexternalhit|whatsapp|telegram|slackbot|discordbot|twitterbot|linkedinbot|embedly|preview|lighthouse|pagespeed|gtmetrix|uptime|pingdom|semrush|ahrefs|mj12|dotbot|petalbot|bytespider|applebot|duckduck|yandex|baidu/i;

function limpar() {
    const agora = Date.now();
    for (const [chave, quando] of vistos) {
        if (agora - quando > JANELA_MS) vistos.delete(chave);
    }
}

function identificadorDiario(req) {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const ua = req.headers['user-agent'] || '';
    const dia = new Date().toISOString().slice(0, 10);
    // Hash com o dia embutido: muda sozinho a cada 24 horas e não
    // permite reconstruir o IP de origem.
    return crypto.createHash('sha256').update(`${ip}|${ua}|${dia}|perfil`).digest('hex').slice(0, 16);
}

function origemLegivel(referrer) {
    if (!referrer) return 'Acesso direto ou link colado';
    try {
        const host = new URL(referrer).hostname.replace(/^www\./, '');
        const conhecidos = {
            'linkedin.com': 'LinkedIn',
            'lnkd.in': 'LinkedIn',
            'google.com': 'Busca no Google',
            'google.com.br': 'Busca no Google',
            'bing.com': 'Busca no Bing',
            'duckduckgo.com': 'Busca no DuckDuckGo',
            'github.com': 'GitHub',
            'youtube.com': 'YouTube',
            'instagram.com': 'Instagram',
            'facebook.com': 'Facebook',
            't.co': 'X',
            'urnau.com.br': 'Outra página do site'
        };
        for (const [dominio, nome] of Object.entries(conhecidos)) {
            if (host === dominio || host.endsWith('.' + dominio)) return nome;
        }
        return host;
    } catch {
        return 'Origem não identificada';
    }
}

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ erro: 'Use POST' });
    }

    // Só aceita chamada vinda do próprio site.
    const origem = req.headers.origin || '';
    const permitidas = ['https://urnau.com.br', 'https://www.urnau.com.br'];
    const local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origem);
    if (origem && !permitidas.includes(origem) && !local) {
        return res.status(403).json({ erro: 'Origem não autorizada' });
    }

    const ua = req.headers['user-agent'] || '';
    if (!ua || PADROES_ROBO.test(ua)) {
        return res.status(204).end();
    }

    let corpo = req.body;
    if (typeof corpo === 'string') {
        try { corpo = JSON.parse(corpo); } catch { corpo = {}; }
    }
    corpo = corpo || {};

    // Sinais coletados no navegador. Sem interação real e sem
    // permanência mínima, não é visita de pessoa.
    const sinais = Number(corpo.sinais) || 0;
    const segundos = Number(corpo.segundos) || 0;
    const automacao = corpo.automacao === true;
    if (automacao || sinais < 2 || segundos < 8) {
        return res.status(204).end();
    }

    if (Date.now() - inicioContagem > 60 * 60 * 1000) {
        contador = 0;
        inicioContagem = Date.now();
    }
    if (contador >= TETO_POR_HORA) return res.status(204).end();

    limpar();
    const id = identificadorDiario(req);
    if (vistos.has(id)) return res.status(204).end();
    vistos.set(id, Date.now());

    if (!WEBHOOK) {
        return res.status(503).json({ erro: 'Webhook não configurado' });
    }

    const pais = req.headers['x-vercel-ip-country'] || null;
    const regiao = req.headers['x-vercel-ip-country-region'] || null;
    const cidade = req.headers['x-vercel-ip-city'] || null;
    const local_txt = [cidade && decodeURIComponent(cidade), regiao, pais].filter(Boolean).join(', ') || 'Não informado';

    const campos = [
        { name: 'Veio de', value: origemLegivel(corpo.referrer), inline: true },
        { name: 'Região aproximada', value: local_txt, inline: true },
        { name: 'Dispositivo', value: corpo.movel ? 'Celular ou tablet' : 'Computador', inline: true },
        { name: 'Tempo na página', value: `${Math.round(segundos)} segundos`, inline: true },
        { name: 'Profundidade de leitura', value: `${Math.min(100, Math.round(Number(corpo.rolagem) || 0))}%`, inline: true },
        { name: 'Seção mais vista', value: String(corpo.secao || 'não identificada').slice(0, 60), inline: true }
    ];

    if (corpo.campanha) {
        campos.push({ name: 'Campanha', value: String(corpo.campanha).slice(0, 80), inline: false });
    }

    const payload = {
        username: 'urnau.com.br',
        embeds: [{
            title: 'Visita no perfil',
            description: 'Alguém com comportamento de pessoa real acabou de ler a página.',
            color: 0x5eead4,
            fields: campos,
            footer: { text: 'urnau.com.br/perfil' },
            timestamp: new Date().toISOString()
        }]
    };

    try {
        const resposta = await fetch(WEBHOOK, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload)
        });
        contador++;
        if (!resposta.ok) {
            console.error('Discord respondeu', resposta.status);
            return res.status(502).json({ erro: 'Falha ao notificar' });
        }
    } catch (e) {
        console.error('Erro ao chamar o webhook:', e.message);
        return res.status(502).json({ erro: 'Falha ao notificar' });
    }

    return res.status(204).end();
};
