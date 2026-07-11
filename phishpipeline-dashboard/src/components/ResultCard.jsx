const STAGE_BADGE_TEXT = {
  URL_ONLY: "Stage 1 — URL Only",
  URL_ONLY_FALLBACK: "Stage 1 — URL Only",
  HYBRID: "Stage 2 — URL + HTML",
};

// Maps the raw flag keys returned by services/html_parser.py's
// adversarial-patch checks to the human-readable labels shown in the
// "Adversarial Signals Detected" panel.
const FLAG_LABELS = {
  js_redirect_early: "JS Redirect (window.location)",
  hidden_iframe: "Hidden iframe detected",
  base64_script_block: "Base64 encoded script block",
  domain_mismatch_links: "Mismatched link domains",
  hidden_text_css: "Hidden text via CSS",
};

function ShieldIcon({ size, fill, stroke, strokeWidth = 1.6, children }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2.5 L19.5 5.6 V11 C19.5 16.2 16.3 19.4 12 21.5 C7.7 19.4 4.5 16.2 4.5 11 V5.6 Z"
        fill={fill}
        stroke={stroke}
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
      />
      {children}
    </svg>
  );
}

function ConfidenceBar({ percent, trackColor, fillColor }) {
  return (
    <div className="rc-bar-track" style={{ background: trackColor }}>
      <div
        className="rc-bar-fill"
        style={{ width: `${percent}%`, background: fillColor }}
      />
    </div>
  );
}

function StageBadge({ background, children }) {
  return (
    <span className="rc-stage-badge" style={{ background }}>
      {children}
    </span>
  );
}

function ClassifyingCard() {
  return (
    <div className="rc-card rc-card-classifying">
      <div className="rc-header">
        <div className="rc-ring">
          <ShieldIcon
            size={26}
            fill="rgba(46,117,182,.25)"
            stroke="#2E75B6"
          />
        </div>
        <div className="rc-title-classifying">Classifying URL...</div>
        <div className="rc-subtitle">Stage 1 — URL Analysis</div>
      </div>
      <div className="rc-shimmer" style={{ height: 22, width: "70%", margin: "0 auto" }} />
      <div className="rc-shimmer" style={{ height: 6, width: "100%" }} />
      <div className="rc-shimmer" style={{ height: 13, width: "85%", margin: "0 auto" }} />
      <div className="rc-shimmer" style={{ height: 34, width: "100%" }} />
    </div>
  );
}

function CleanCard({ url, confidence, stage, classifiedIn }) {
  const percent = Math.round((confidence || 0) * 100);

  return (
    <div className="rc-card rc-card-clean">
      <div className="rc-header">
        <ShieldIcon size={46} fill="rgba(0,100,0,.22)" stroke="#1F9D4F">
          <path
            d="M8.7 12 L11 14.4 L15.4 9.4"
            stroke="#3FDC7F"
            strokeWidth="1.9"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </ShieldIcon>
        <div className="rc-title-clean">CLEAN</div>
      </div>

      <div className="rc-confidence-block">
        <ConfidenceBar percent={percent} trackColor="#162233" fillColor="#1F9D4F" />
        <div className="rc-confidence-text">{percent}% confidence</div>
      </div>

      <div>
        <StageBadge background="#2E75B6">
          {STAGE_BADGE_TEXT[stage] || "Stage 1 — URL Only"}
        </StageBadge>
      </div>

      <div className="rc-url">{url}</div>
      <div className="rc-classified-in">Classified in {classifiedIn}</div>
    </div>
  );
}

function EscalatingCard({ confidence }) {
  const percent = Math.round((confidence || 0) * 100);

  return (
    <div className="rc-card rc-card-escalating">
      <div className="rc-header">
        <ShieldIcon size={46} fill="rgba(180,83,9,.2)" stroke="#B45309">
          <path
            d="M12 8 V13"
            stroke="#F0A93B"
            strokeWidth="1.9"
            strokeLinecap="round"
          />
          <circle cx="12" cy="16.2" r="1.05" fill="#F0A93B" />
        </ShieldIcon>
        <div className="rc-title-escalating">ESCALATING TO STAGE 2</div>
      </div>

      <div className="rc-confidence-block">
        <ConfidenceBar percent={percent} trackColor="#162233" fillColor="#B45309" />
        <div className="rc-confidence-text">
          {percent}% confidence — below threshold (0.70)
        </div>
      </div>

      <div>
        <StageBadge background="#B45309">Stage 1 → Stage 2</StageBadge>
      </div>

      <div className="rc-spinner-row">
        <span className="rc-spinner" />
        <span className="rc-spinner-text">Fetching HTML for deep scan...</span>
      </div>
    </div>
  );
}

function PhishingCard({ url, confidence, stage, adversarialFlags, classifiedIn }) {
  const percent = Math.round((confidence || 0) * 100);
  const flags = adversarialFlags || [];

  return (
    <div className="rc-card rc-card-phishing">
      <div className="rc-header">
        <ShieldIcon size={52} fill="rgba(192,0,0,.22)" stroke="#C00000" strokeWidth={1.7}>
          <path
            d="M12 7.8 V13.4"
            stroke="#FF6B6B"
            strokeWidth="2.1"
            strokeLinecap="round"
          />
          <circle cx="12" cy="17" r="1.15" fill="#FF6B6B" />
        </ShieldIcon>
        <div className="rc-title-phishing">PHISHING DETECTED</div>
      </div>

      <div className="rc-confidence-block">
        <ConfidenceBar percent={percent} trackColor="#162233" fillColor="#C00000" />
        <div className="rc-confidence-text">
          {percent}% confidence — {stage === "HYBRID" ? "Stage 2 (Hybrid)" : "Stage 1"}
        </div>
      </div>

      <div>
        <StageBadge background="#7B2FBE">
          {STAGE_BADGE_TEXT[stage] || "Stage 2 — URL + HTML"}
        </StageBadge>
      </div>

      {flags.length > 0 && (
        <div className="rc-signals-panel">
          <div className="rc-signals-header">Adversarial Signals Detected</div>
          {flags.map((flag) => (
            <div key={flag} className="rc-signal-row">
              <span className="rc-signal-icon">⚠</span>
              <span>{FLAG_LABELS[flag] || flag}</span>
            </div>
          ))}
        </div>
      )}

      {url && <div className="rc-url rc-url-phishing">{url}</div>}
      {classifiedIn && (
        <div className="rc-classified-in">Classified in {classifiedIn}</div>
      )}

      <div className="rc-actions">
        <button type="button" className="rc-btn-report">
          Report Now
        </button>
        <button type="button" className="rc-btn-ghost">
          View Full Analysis
        </button>
      </div>
    </div>
  );
}

function ResultCard({
  state,
  url,
  confidence = 0,
  stage = "URL_ONLY",
  adversarialFlags = [],
  classifiedIn = "0.3s",
}) {
  if (state === "classifying") {
    return <ClassifyingCard />;
  }
  if (state === "clean") {
    return (
      <CleanCard
        url={url}
        confidence={confidence}
        stage={stage}
        classifiedIn={classifiedIn}
      />
    );
  }
  if (state === "escalating") {
    return <EscalatingCard confidence={confidence} />;
  }
  if (state === "phishing") {
    return (
      <PhishingCard
        url={url}
        confidence={confidence}
        stage={stage}
        adversarialFlags={adversarialFlags}
        classifiedIn={classifiedIn}
      />
    );
  }
  return null;
}

export default ResultCard;
