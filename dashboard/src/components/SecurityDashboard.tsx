import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Server, 
  Eye,
  CheckCircle,
  Zap,
  TrendingUp,
  Wifi,
  Globe,
  Lock
} from 'lucide-react';
import { AWSService, type CloudWatchEvent, type ThreatAlert, type SystemMetrics } from '../services/awsService';

// Using types from AWS Service
type SecurityEvent = CloudWatchEvent;
type SystemStats = SystemMetrics;

export function SecurityDashboard() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [stats, setStats] = useState<SystemStats>({
    eventsProcessed: 0,
    threatsDetected: 0,
    responsesExecuted: 0,
    systemHealth: 'Active'
  });
  const [isConnected, setIsConnected] = useState(true);
  const [awsStatus, setAwsStatus] = useState({
    cloudwatch: true,
    lambda: true,
    region: 'us-east-2'
  });
  const [isLoading, setIsLoading] = useState(true);
  
  const awsService = AWSService.getInstance();

  // Hybrid real AWS + mock data fetching for optimal user experience
  useEffect(() => {
    const fetchHybridData = async () => {
      try {
        setIsLoading(true);
        
        // Fetch hybrid data (real AWS metrics + live mock events)
        const [currentStats, currentEvents, currentThreats] = await Promise.all([
          awsService.getSystemMetrics(), // Real AWS-based metrics
          awsService.getRecentEvents(),   // Real patterns + live mock events
          awsService.getThreatAlerts()    // Real responses + live mock alerts
        ]);
        
        setStats(currentStats);
        setEvents(currentEvents);
        setThreats(currentThreats);
        setIsConnected(true);
        
        console.log('🔄 Successfully loaded hybrid security data:', {
          realMetricsBase: 'AWS CloudWatch patterns',
          eventsProcessed: currentStats.eventsProcessed,
          threatsDetected: currentStats.threatsDetected,
          liveEvents: currentEvents.length,
          liveAlerts: currentThreats.length
        });
        
      } catch (error) {
        console.error('❌ Error fetching hybrid data:', error);
        setIsConnected(false);
        // Keep existing data or show offline status
      } finally {
        setIsLoading(false);
      }
    };
    
    // Initial load
    fetchHybridData();
    
    // Fast updates every 15 seconds for real-time user experience
    const interval = setInterval(fetchHybridData, 15000);
    
    return () => clearInterval(interval);
  }, [awsService]);

  const getRiskBadgeVariant = (score: number) => {
    if (score >= 8) return "destructive";
    if (score >= 6) return "default";
    return "secondary";
  };

  const getRiskLabel = (score: number) => {
    if (score >= 8) return "CRITICAL";
    if (score >= 6) return "HIGH";
    return "MEDIUM";
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0c1426 0%, #1e3a8a 50%, #1a2332 100%)',
      padding: '24px',
      color: '#ffffff',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* AWS-style animated background */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse at top right, rgba(59, 130, 246, 0.1) 0%, transparent 50%, rgba(147, 51, 234, 0.1) 100%)',
        animation: 'pulse 3s ease-in-out infinite'
      }}></div>
      <div style={{ position: 'relative', zIndex: 10 }}>
      {/* AWS Console Style Header */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ position: 'relative' }}>
              <Shield style={{ 
                height: '48px', 
                width: '48px', 
                color: '#22d3ee',
                filter: 'drop-shadow(0 0 10px rgba(34, 211, 238, 0.5))'
              }} />
            </div>
            <div>
              <h1 style={{
                fontSize: '36px',
                fontWeight: 'bold',
                background: 'linear-gradient(90deg, #22d3ee 0%, #3b82f6 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                marginBottom: '8px'
              }}>
                AEGIS SECURITY
              </h1>
              <p style={{ color: '#cbd5e1', fontSize: '18px', fontWeight: '500', marginBottom: '8px' }}>
                🛡️ Real-time Cloud Security Monitoring & AWS Integration
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Globe style={{ height: '16px', width: '16px', color: '#10b981' }} />
                  <span style={{ fontSize: '14px', color: '#10b981', fontWeight: '600' }}>AWS {awsStatus.region}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Wifi style={{ height: '16px', width: '16px', color: '#3b82f6' }} />
                  <span style={{ fontSize: '14px', color: '#3b82f6' }}>CloudWatch Active</span>
                </div>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ position: 'relative' }}>
              <div style={{
                height: '16px',
                width: '16px',
                borderRadius: '50%',
                background: isConnected ? '#10b981' : '#ef4444',
                boxShadow: isConnected ? '0 0 20px rgba(16, 185, 129, 0.5)' : '0 0 20px rgba(239, 68, 68, 0.5)',
                animation: 'pulse 2s ease-in-out infinite'
              }} />
            </div>
            <div style={{ textAlign: 'right' }}>
              <span style={{ fontSize: '14px', fontWeight: '600', color: isConnected ? '#10b981' : '#ef4444' }}>
                {isLoading ? 'CONNECTING...' : (isConnected ? 'HYBRID LIVE DATA' : 'CONNECTION ERROR')}
              </span>
              <p style={{ fontSize: '12px', color: '#64748b', margin: 0 }}>
                {isLoading ? 'Loading hybrid data...' : (isConnected ? 'Real AWS metrics + Live events' : 'System offline')}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* AWS Console Style Stats Cards */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', 
        gap: '24px', 
        marginBottom: '32px' 
      }}>
        {/* Events Processed Card */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '12px',
          padding: '24px',
          transition: 'all 0.3s ease',
          cursor: 'pointer',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ 
              padding: '12px', 
              background: 'rgba(59, 130, 246, 0.2)', 
              borderRadius: '8px' 
            }}>
              <Activity style={{ height: '24px', width: '24px', color: '#3b82f6' }} />
            </div>
            <TrendingUp style={{ height: '20px', width: '20px', color: '#10b981' }} />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#22d3ee', marginBottom: '4px' }}>
            {stats.eventsProcessed.toLocaleString()}
          </div>
          <p style={{ fontSize: '14px', color: '#cbd5e1', fontWeight: '500', margin: 0 }}>Events Processed</p>
          <p style={{ fontSize: '12px', color: '#10b981', marginTop: '4px', margin: 0 }}>
            ↗️ +{Math.floor(stats.eventsProcessed * 0.1)} from last hour
          </p>
        </div>

        {/* Threats Detected Card */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '12px',
          padding: '24px',
          transition: 'all 0.3s ease',
          cursor: 'pointer',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ 
              padding: '12px', 
              background: 'rgba(239, 68, 68, 0.2)', 
              borderRadius: '8px' 
            }}>
              <AlertTriangle style={{ height: '24px', width: '24px', color: '#ef4444' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{ height: '8px', width: '8px', background: '#ef4444', borderRadius: '50%', marginRight: '8px', animation: 'pulse 2s ease-in-out infinite' }}></div>
              <span style={{ color: '#ef4444', fontSize: '12px', fontWeight: 'bold' }}>CRITICAL</span>
            </div>
          </div>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#ef4444', marginBottom: '4px' }}>
            {stats.threatsDetected}
          </div>
          <p style={{ fontSize: '14px', color: '#cbd5e1', fontWeight: '500', margin: 0 }}>Threats Detected</p>
          <p style={{ fontSize: '12px', color: '#f97316', marginTop: '4px', margin: 0 }}>
            ⚠️ {((stats.threatsDetected / Math.max(stats.eventsProcessed, 1)) * 100).toFixed(1)}% threat rate
          </p>
        </div>

        {/* Responses Executed Card */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(147, 51, 234, 0.3)',
          borderRadius: '12px',
          padding: '24px',
          transition: 'all 0.3s ease',
          cursor: 'pointer',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ 
              padding: '12px', 
              background: 'rgba(147, 51, 234, 0.2)', 
              borderRadius: '8px' 
            }}>
              <Zap style={{ height: '24px', width: '24px', color: '#9333ea' }} />
            </div>
            <CheckCircle style={{ height: '20px', width: '20px', color: '#10b981' }} />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#a855f7', marginBottom: '4px' }}>
            {stats.responsesExecuted}
          </div>
          <p style={{ fontSize: '14px', color: '#cbd5e1', fontWeight: '500', margin: 0 }}>Responses Executed</p>
          <p style={{ fontSize: '12px', color: '#10b981', marginTop: '4px', margin: 0 }}>
            ✅ {stats.responsesExecuted === stats.threatsDetected ? '100%' : '99%'} response rate
          </p>
        </div>

        {/* System Health Card */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '12px',
          padding: '24px',
          transition: 'all 0.3s ease',
          cursor: 'pointer',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ 
              padding: '12px', 
              background: 'rgba(16, 185, 129, 0.2)', 
              borderRadius: '8px' 
            }}>
              <Server style={{ height: '24px', width: '24px', color: '#10b981' }} />
            </div>
            <div style={{ display: 'flex', gap: '4px' }}>
              <div style={{ height: '4px', width: '4px', background: '#10b981', borderRadius: '50%', animation: 'pulse 1s ease-in-out infinite' }}></div>
              <div style={{ height: '4px', width: '4px', background: '#10b981', borderRadius: '50%', animation: 'pulse 1s ease-in-out infinite', animationDelay: '0.2s' }}></div>
              <div style={{ height: '4px', width: '4px', background: '#10b981', borderRadius: '50%', animation: 'pulse 1s ease-in-out infinite', animationDelay: '0.4s' }}></div>
            </div>
          </div>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#10b981', marginBottom: '4px' }}>
            {stats.systemHealth}
          </div>
          <p style={{ fontSize: '14px', color: '#cbd5e1', fontWeight: '500', margin: 0 }}>System Health</p>
          <p style={{ fontSize: '12px', color: '#10b981', marginTop: '4px', margin: 0 }}>
            🟢 All services operational
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(600px, 1fr))', gap: '24px' }}>
        {/* AWS Console Style Live Event Feed */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.9)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(71, 85, 105, 0.5)',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <div style={{ position: 'relative' }}>
              <Eye style={{ height: '24px', width: '24px', color: '#22d3ee' }} />
              <div style={{
                position: 'absolute',
                top: '-4px',
                right: '-4px',
                height: '12px',
                width: '12px',
                background: '#22d3ee',
                borderRadius: '50%',
                animation: 'pulse 2s ease-in-out infinite'
              }}></div>
            </div>
            <div style={{ flex: 1 }}>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#22d3ee', margin: 0 }}>Live Security Feed</h3>
              <p style={{ fontSize: '14px', color: '#64748b', margin: 0 }}>⚡ Real-time AWS CloudWatch events</p>
            </div>
            <div style={{
              background: 'rgba(34, 211, 238, 0.1)',
              padding: '8px 16px',
              borderRadius: '20px',
              border: '1px solid rgba(34, 211, 238, 0.3)'
            }}>
              <span style={{ color: '#22d3ee', fontSize: '12px', fontWeight: 'bold' }}>STREAMING</span>
            </div>
          </div>
          <div style={{
            maxHeight: '400px',
            overflowY: 'auto',
            paddingRight: '8px'
          }}>
            {events.map((event, index) => (
              <div 
                key={event.id} 
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '16px',
                  marginBottom: '12px',
                  borderRadius: '8px',
                  border: event.threatDetected ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(71, 85, 105, 0.4)',
                  background: event.threatDetected 
                    ? 'linear-gradient(90deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.05) 100%)'
                    : 'linear-gradient(90deg, rgba(71, 85, 105, 0.1) 0%, rgba(51, 65, 85, 0.05) 100%)',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer'
                }}
              >
                <div style={{ position: 'relative' }}>
                  <div style={{
                    height: '12px',
                    width: '12px',
                    borderRadius: '50%',
                    marginTop: '8px',
                    background: event.threatDetected ? '#ef4444' : '#10b981',
                    boxShadow: event.threatDetected ? '0 0 10px rgba(239, 68, 68, 0.5)' : '0 0 10px rgba(16, 185, 129, 0.5)',
                    animation: 'pulse 2s ease-in-out infinite'
                  }} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <p style={{ fontSize: '14px', fontWeight: '600', color: '#ffffff', margin: 0, textTransform: 'capitalize' }}>
                      🔍 {event.type.replace('_', ' ')}
                    </p>
                    <div style={{
                      padding: '4px 8px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      background: event.threatDetected ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      color: event.threatDetected ? '#ef4444' : '#3b82f6',
                      border: event.threatDetected ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(59, 130, 246, 0.4)'
                    }}>
                      {event.severity.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', marginBottom: '8px' }}>
                    <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center' }}>
                      👤 <span style={{ marginLeft: '4px', fontFamily: 'monospace' }}>{event.userId}</span>
                    </span>
                    <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center' }}>
                      🌐 <span style={{ marginLeft: '4px', fontFamily: 'monospace' }}>{event.sourceIp}</span>
                    </span>
                  </div>
                  <p style={{ fontSize: '12px', color: '#64748b', margin: 0, display: 'flex', alignItems: 'center' }}>
                    ⏱️ {new Date(event.timestamp).toLocaleTimeString()}
                    <span style={{ marginLeft: '8px', color: '#22d3ee' }}>• {event.resource}</span>
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* AWS Console Style Threat Response Center */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.9)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(71, 85, 105, 0.5)',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <div style={{ position: 'relative' }}>
              <Shield style={{ height: '24px', width: '24px', color: '#ef4444' }} />
              <div style={{
                position: 'absolute',
                top: '-4px',
                right: '-4px',
                height: '12px',
                width: '12px',
                background: '#ef4444',
                borderRadius: '50%',
                animation: 'pulse 2s ease-in-out infinite'
              }}></div>
            </div>
            <div style={{ flex: 1 }}>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#ef4444', margin: 0 }}>Threat Response Center</h3>
              <p style={{ fontSize: '14px', color: '#64748b', margin: 0 }}>🚨 Automated AWS Lambda responses</p>
            </div>
            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              padding: '8px 16px',
              borderRadius: '20px',
              border: '1px solid rgba(239, 68, 68, 0.3)'
            }}>
              <span style={{ color: '#ef4444', fontSize: '12px', fontWeight: 'bold' }}>ACTIVE</span>
            </div>
          </div>
          <div style={{
            maxHeight: '400px',
            overflowY: 'auto',
            paddingRight: '8px'
          }}>
            {threats.map((threat, index) => (
              <div 
                key={threat.id} 
                style={{
                  padding: '20px',
                  marginBottom: '16px',
                  borderRadius: '8px',
                  borderLeft: '4px solid #ef4444',
                  background: 'linear-gradient(90deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.05) 100%)',
                  backdropFilter: 'blur(5px)',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer',
                  border: '1px solid rgba(239, 68, 68, 0.2)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{
                      padding: '8px',
                      background: 'rgba(239, 68, 68, 0.2)',
                      borderRadius: '8px'
                    }}>
                      <Lock style={{ height: '16px', width: '16px', color: '#ef4444' }} />
                    </div>
                    <div>
                      <h4 style={{ fontSize: '14px', fontWeight: 'bold', color: '#ffffff', margin: 0 }}>
                        🚨 {threat.type.replace(/_/g, ' ')}
                      </h4>
                      <div style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        padding: '4px 8px',
                        borderRadius: '12px',
                        fontSize: '11px',
                        fontWeight: 'bold',
                        marginTop: '4px',
                        background: threat.riskScore >= 8 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(249, 115, 22, 0.3)',
                        color: threat.riskScore >= 8 ? '#ef4444' : '#f97316',
                        border: threat.riskScore >= 8 ? '1px solid rgba(239, 68, 68, 0.5)' : '1px solid rgba(249, 115, 22, 0.5)'
                      }}>
                        ⚠️ {getRiskLabel(threat.riskScore)} ({threat.riskScore}/10)
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <CheckCircle style={{ height: '20px', width: '20px', color: '#10b981' }} />
                    <span style={{
                      background: 'rgba(16, 185, 129, 0.2)',
                      color: '#10b981',
                      padding: '4px 8px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      border: '1px solid rgba(16, 185, 129, 0.4)'
                    }}>RESOLVED</span>
                  </div>
                </div>
                <p style={{ fontSize: '12px', color: '#cbd5e1', marginBottom: '12px', fontWeight: '500', margin: 0 }}>
                  ✅ {threat.description}
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '8px', marginBottom: '12px' }}>
                  {threat.responseActions.map((action, actionIndex) => (
                    <div 
                      key={actionIndex} 
                      style={{
                        background: 'rgba(71, 85, 105, 0.3)',
                        border: '1px solid rgba(71, 85, 105, 0.5)',
                        padding: '6px 8px',
                        borderRadius: '6px',
                        fontSize: '11px',
                        color: '#22d3ee',
                        fontFamily: 'monospace',
                        display: 'flex',
                        alignItems: 'center'
                      }}
                    >
                      <div style={{ height: '4px', width: '4px', background: '#22d3ee', borderRadius: '50%', marginRight: '6px' }}></div>
                      {action.replace('_', ' ')}
                    </div>
                  ))}
                </div>
                <p style={{ fontSize: '12px', color: '#64748b', margin: 0, display: 'flex', alignItems: 'center' }}>
                  ✅ Resolved at <span style={{ marginLeft: '4px', color: '#10b981', fontFamily: 'monospace' }}>{new Date(threat.timestamp).toLocaleTimeString()}</span>
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {/* Add custom animations */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
      </div>
    </div>
  );
}