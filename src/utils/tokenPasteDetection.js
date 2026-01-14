export class TokenPasteDetection {
  static PATTERNS = {
    botToken: /^[MN][A-Za-z\d_-]{24,25}\.[\w-]{6,7}\.[\w-]{27,38}$/,
    userToken: /^[\w-]{26}\.[\w-]{6}\.[\w-]{25,35}$/,
    suspiciousString: /^[A-Za-z0-9_-]{30,}$/,
  };

  static isLikelyToken(str) {
    if (!str || typeof str !== 'string' || str.length < 20) {
      return false;
    }
    return (
      this.PATTERNS.botToken.test(str) ||
      this.PATTERNS.userToken.test(str)
    );
  }

  static getRiskLevel(str) {
    if (this.PATTERNS.botToken.test(str)) {
      return { level: 'CRITICAL', type: 'bot_token' };
    }
    if (this.PATTERNS.userToken.test(str)) {
      return { level: 'CRITICAL', type: 'user_token' };
    }
    if (this.PATTERNS.suspiciousString.test(str) && str.length > 30) {
      return { level: 'WARNING', type: 'suspicious_string' };
    }
    return { level: 'SAFE', type: null };
  }

  static createWarning(riskLevel) {
    const warnings = {
      bot_token: {
        title: 'Warning: This looks like a bot token',
        message: 'Do not paste Discord tokens. Bot tokens grant full access to your account.',
        advice: 'Use OAuth2 login instead.',
        action: 'CLEAR'
      },
      user_token: {
        title: 'Warning: User token detected',
        message: 'This appears to be a Discord user token. Pasting tokens is unsafe.',
        advice: 'Use OAuth2 login. If pasted elsewhere, regenerate immediately.',
        action: 'CLEAR'
      },
      suspicious_string: {
        title: 'Suspicious content detected',
        message: 'This might be sensitive data.',
        advice: 'Use OAuth2 login for better security.',
        action: 'CONFIRM'
      }
    };

    return warnings[riskLevel.type] || null;
  }
}

export function useTokenPasteDetection(onDetect) {
  return (e) => {
    const pastedText = e.clipboardData?.getData('text') || '';
    const risk = TokenPasteDetection.getRiskLevel(pastedText);
    
    if (risk.level !== 'SAFE') {
      e.preventDefault();
      const warning = TokenPasteDetection.createWarning(risk);
      onDetect?.(warning, risk);
    }
  };
}
