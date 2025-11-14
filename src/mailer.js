let transporter = null;
let nodemailerModule = null;

async function loadNodemailer() {
  if (nodemailerModule !== null) return nodemailerModule;
  try {
    nodemailerModule = await import("nodemailer");
  } catch (error) {
    nodemailerModule = null;
    console.warn(
      "[mailer] Pacote 'nodemailer' não encontrado. Links de redefinição serão apenas registrados no console."
    );
    console.warn("[mailer] Instale dependências com `npm install` para habilitar emails.");
  }
  return nodemailerModule;
}

async function buildTransporter() {
  if (transporter) return transporter;

  const nodemailer = await loadNodemailer();
  if (!nodemailer) {
    transporter = null;
    return null;
  }

  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
  const secure =
    typeof process.env.SMTP_SECURE !== "undefined"
      ? String(process.env.SMTP_SECURE).toLowerCase() === "true"
      : port === 465;

  if (host && user && pass) {
    transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: {
        user,
        pass
      }
    });
  } else {
    console.warn("[mailer] SMTP não configurado. Usando log local do link.");
    transporter = null;
  }

  return transporter;
}

export async function sendPasswordResetEmail(to, resetUrl) {
  const subject = "NexusAI - redefinição de senha";
  const from =
    process.env.MAIL_FROM ||
    process.env.SMTP_FROM ||
    process.env.SMTP_USER ||
    "no-reply@nexusai.local";

  const text = [
    "Olá,",
    "",
    "Recebemos uma solicitação para redefinir sua senha da NexusAI.",
    "Se você fez essa solicitação, clique no link abaixo (válido por tempo limitado):",
    resetUrl,
    "",
    "Se você não solicitou a troca, ignore este email.",
    "",
    "Equipe NexusAI"
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; color: #0f172a;">
      <p>Olá,</p>
      <p>Recebemos uma solicitação para redefinir sua senha na <strong>NexusAI</strong>.</p>
      <p>
        Se você solicitou essa alteração, clique no botão abaixo (o link expira em breve):
      </p>
      <p>
        <a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;">
          Redefinir senha
        </a>
      </p>
      <p>Ou copie e cole este link no navegador:</p>
      <p style="word-break:break-all;">${resetUrl}</p>
      <p style="margin-top:24px;">Se você não solicitou a troca de senha, ignore esta mensagem.</p>
      <p style="margin-top:16px;">Equipe NexusAI</p>
    </div>
  `;

  const mailTransporter = await buildTransporter();
  if (!mailTransporter) {
    console.warn("[mailer] SMTP não configurado. Link de redefinição:");
    console.info(`[mailer] ${resetUrl}`);
    return;
  }

  await mailTransporter.sendMail({
    to,
    from,
    subject,
    text,
    html
  });
}
