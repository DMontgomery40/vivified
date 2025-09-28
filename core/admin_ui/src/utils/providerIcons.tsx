// Provider icons and utilities
import {
  CloudQueue as CloudIcon,
  Router as SipIcon,
  Science as TestIcon,
  Phone as PhoneIcon,
  Webhook as WebhookIcon,
  Storage as StorageIcon,
  Api as ApiIcon,
} from '@mui/icons-material';

export const getProviderIcon = (providerId: string, size: 'small' | 'medium' | 'large' = 'medium') => {
  const iconProps = {
    fontSize: size,
    sx: { 
      color: getProviderColor(providerId),
      ...(size === 'large' && { fontSize: '2rem' })
    }
  };

  switch (providerId?.toLowerCase()) {
    case 'phaxio':
      return <CloudIcon {...iconProps} />;
    case 'sinch':
      return <ApiIcon {...iconProps} />;
    case 'documo':
      return <WebhookIcon {...iconProps} />;
    case 'signalwire':
      return <PhoneIcon {...iconProps} />;
    case 'sip':
    case 'asterisk':
      return <SipIcon {...iconProps} />;
    case 'freeswitch':
      return <StorageIcon {...iconProps} />;
    case 'disabled':
    case 'test':
      return <TestIcon {...iconProps} />;
    default:
      return <CloudIcon {...iconProps} />;
  }
};

export const getProviderColor = (providerId: string): string => {
  switch (providerId?.toLowerCase()) {
    case 'phaxio':
      return '#2196F3'; // Blue
    case 'sinch':
      return '#FF9800'; // Orange
    case 'documo':
      return '#9C27B0'; // Purple
    case 'signalwire':
      return '#4CAF50'; // Green
    case 'sip':
    case 'asterisk':
      return '#607D8B'; // Blue Grey
    case 'freeswitch':
      return '#795548'; // Brown
    case 'disabled':
    case 'test':
      return '#FFC107'; // Amber
    default:
      return '#757575'; // Grey
  }
};

export const getProviderDisplayName = (providerId: string): string => {
  const names: Record<string, string> = {
    phaxio: 'Phaxio',
    sinch: 'Sinch',
    documo: 'Documo',
    signalwire: 'SignalWire',
    sip: 'SIP/Asterisk',
    asterisk: 'SIP/Asterisk',
    freeswitch: 'FreeSWITCH',
    disabled: 'Test Mode',
    test: 'Test Mode',
  };
  return names[providerId?.toLowerCase()] || providerId || 'Unknown';
};

export const getProviderCategory = (providerId: string): 'cloud' | 'self-hosted' | 'test' => {
  switch (providerId?.toLowerCase()) {
    case 'phaxio':
    case 'sinch':
    case 'documo':
    case 'signalwire':
      return 'cloud';
    case 'sip':
    case 'asterisk':
    case 'freeswitch':
      return 'self-hosted';
    case 'disabled':
    case 'test':
      return 'test';
    default:
      return 'cloud';
  }
};
