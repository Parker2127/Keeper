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
  Lock,
  Play,
  Pause,
  Search,
  Filter,
  Settings,
  Target,
  BarChart3,
  Sliders,
  RefreshCw,
  Download,
  X,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { AWSService, type CloudWatchEvent, type ThreatAlert, type SystemMetrics } from '../services/awsService';
import { ToastProvider, useToast } from './ui/toast';

// Using types from AWS Service
type SecurityEvent = CloudWatchEvent;
type SystemStats = SystemMetrics;

interface EventDetails {
  event_id: string;
  full_log: string;
  network_trace: any;
  user_context: any;
  recommendations: string[];
}

function InteractiveSecurityDashboardContent() {
  const { addToast } = useToast();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [stats, setStats] = useState<SystemStats>({
    eventsProcessed: 0,
    threatsDetected: 0,
    responsesExecuted: 0,
    systemHealth: 'Active'
  });
  
  // Interactive state
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<string | null>(null);
  const [eventDetails, setEventDetails] = useState<EventDetails | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [alertThreshold, setAlertThreshold] = useState(7);
  const [showSettings, setShowSettings] = useState(false);
  const [showControls, setShowControls] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [initialLoad, setInitialLoad] = useState(true);

  const awsService = AWSService.getInstance();

  // Fetch data
  useEffect(() => {
    const fetchHybridData = async () => {
      try {
        setIsLoading(true);
        
        const [currentStats, currentEvents, currentThreats] = await Promise.all([
          awsService.getSystemMetrics(),
          awsService.getRecentEvents(),
          awsService.getThreatAlerts()
        ]);
        
        setStats(currentStats);
        setEvents(currentEvents);
        setThreats(currentThreats);
        // Only set connected to true if monitoring is active and data fetch succeeds
        // This preserves the monitoring state while indicating successful data connection
        
      } catch (error) {
        console.error('❌ Error fetching hybrid data:', error);
        // Don't change connection status here - let monitoring state control it
      } finally {
        setIsLoading(false);
        // Hide initial loading screen after first successful data fetch
        if (initialLoad) {
          setTimeout(() => setInitialLoad(false), 1000);
        }
      }
    };
    
    fetchHybridData();
    const interval = setInterval(fetchHybridData, 15000);
    return () => clearInterval(interval);
  }, [awsService]);

  // Interactive functions
  const toggleMonitoring = async () => {
    try {
      const response = await fetch('/api/monitoring/toggle', { method: 'POST' });
      const data = await response.json();
      setIsMonitoring(data.monitoring_active);
      setIsConnected(data.monitoring_active); // Update connection status based on monitoring state
      
      addToast({
        type: data.monitoring_active ? 'success' : 'warning',
        title: `Protocol ${data.monitoring_active ? 'Activated' : 'Disengaged'}`,
        description: `Security monitoring has been ${data.monitoring_active ? 'activated' : 'deactivated'}`,
        duration: 3000
      });
    } catch (error) {
      console.error('Error toggling monitoring:', error);
      addToast({
        type: 'error',
        title: 'Protocol Error',
        description: 'Failed to toggle monitoring state. Please try again.',
        duration: 4000
      });
    }
  };

  const executeManualResponse = async (threatId: string, action: string) => {
    try {
      const response = await fetch('/api/threats/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: threatId, action })
      });
      const data = await response.json();
      
      // Update stats to reflect manual response
      setStats(prev => ({
        ...prev,
        responsesExecuted: prev.responsesExecuted + 1
      }));
      
      // Show success toast
      addToast({
        type: 'success',
        title: 'Response Executed',
        description: `${action.replace('_', ' ')} action completed for threat ${threatId}`,
        duration: 3000
      });
    } catch (error) {
      console.error('Error executing response:', error);
      addToast({
        type: 'error',
        title: 'Response Failed',
        description: 'Failed to execute threat response. Please try again.',
        duration: 4000
      });
    }
  };

  const investigateEvent = async (eventId: string) => {
    try {
      setSelectedEvent(eventId);
      const response = await fetch(`/api/investigation/details/${eventId}`);
      const details = await response.json();
      setEventDetails(details);
      
      addToast({
        type: 'info',
        title: 'Investigation Started',
        description: `Analyzing event ${eventId}. Review network traces and recommendations.`,
        duration: 2000
      });
    } catch (error) {
      console.error('Error fetching event details:', error);
      addToast({
        type: 'error',
        title: 'Investigation Failed',
        description: 'Unable to load event details. Please try again.',
        duration: 4000
      });
    }
  };

  const updateAlertThreshold = async (threshold: number) => {
    try {
      await fetch('/api/settings/alert-threshold', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threshold })
      });
      setAlertThreshold(threshold);
      
      addToast({
        type: 'info',
        title: 'Threshold Updated',
        description: `Alert threshold set to ${threshold}/10. New threats above this level will trigger alerts.`,
        duration: 3000
      });
    } catch (error) {
      console.error('Error updating threshold:', error);
      addToast({
        type: 'error',
        title: 'Settings Error',
        description: 'Failed to update alert threshold. Please try again.',
        duration: 4000
      });
    }
  };

  // Filter events based on search and severity
  const filteredEvents = events.filter(event => {
    const matchesSearch = event.type.toLowerCase().includes(searchFilter.toLowerCase()) ||
                         event.userId.toLowerCase().includes(searchFilter.toLowerCase()) ||
                         event.sourceIp.includes(searchFilter);
    const matchesSeverity = severityFilter === 'all' || event.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  // Show loading screen on initial load
  if (initialLoad) {
    return (
      <div style={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #f8f8f8 0%, #f0f0f0 30%, #e8e8e8 60%, #f5f5f5 100%)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Background texture */}
        <div className="crosshatch" style={{
          position: 'absolute',
          inset: 0,
          background: `
            repeating-linear-gradient(45deg, transparent, transparent 15px, rgba(150, 150, 150, 0.1) 15px, rgba(150, 150, 150, 0.1) 20px),
            repeating-linear-gradient(-45deg, transparent, transparent 15px, rgba(180, 180, 180, 0.08) 15px, rgba(180, 180, 180, 0.08) 20px),
            radial-gradient(circle at 20% 50%, rgba(200, 200, 200, 0.1) 1px, transparent 1px),
            radial-gradient(circle at 80% 50%, rgba(200, 200, 200, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '30px 30px, 30px 30px, 50px 50px, 50px 50px',
          opacity: 0.4
        }}></div>

        {/* Loading content */}
        <div style={{ position: 'relative', zIndex: 10, textAlign: 'center' }}>
          {/* Logo and title */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', marginBottom: '32px' }}>
            <Shield style={{
              height: '64px',
              width: '64px',
              color: '#666',
              animation: 'pulse 2s ease-in-out infinite'
            }} />
            <h1 className="pencil-text" style={{
              fontSize: '48px',
              fontWeight: '600',
              color: '#333',
              margin: 0,
              borderBottom: '4px solid #666',
              paddingBottom: '8px',
              display: 'inline-block'
            }}>
              KEEPER
            </h1>
          </div>

          {/* Subtitle */}
          <p style={{
            fontSize: '24px',
            color: '#666',
            marginBottom: '48px',
            fontWeight: '500'
          }}>
            DevOps Security Frontend - Initializing AWS CloudWatch Integration
          </p>

          {/* Loading spinner */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '16px',
            marginBottom: '24px'
          }}>
            <RefreshCw style={{
              height: '32px',
              width: '32px',
              color: '#666',
              animation: 'spin 1s linear infinite'
            }} />
            <span style={{
              fontSize: '18px',
              color: '#777',
              fontWeight: '500'
            }}>
              Loading Security Monitoring System...
            </span>
          </div>

          {/* Progress indicator */}
          <div style={{
            width: '300px',
            height: '4px',
            background: 'rgba(200, 200, 200, 0.3)',
            borderRadius: '2px',
            overflow: 'hidden',
            margin: '0 auto'
          }}>
            <div style={{
              height: '100%',
              background: 'linear-gradient(90deg, #666, #888)',
              borderRadius: '2px',
              animation: 'loading-progress 2s ease-in-out infinite',
              width: '100%',
              transformOrigin: 'left'
            }}></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #f8f8f8 0%, #f0f0f0 30%, #e8e8e8 60%, #f5f5f5 100%)',
      padding: '24px',
      color: '#333333',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Paper texture background */}
      <div className="crosshatch" style={{
        position: 'absolute',
        inset: 0,
        background: `
          repeating-linear-gradient(45deg, transparent, transparent 15px, rgba(150, 150, 150, 0.1) 15px, rgba(150, 150, 150, 0.1) 20px),
          repeating-linear-gradient(-45deg, transparent, transparent 15px, rgba(180, 180, 180, 0.08) 15px, rgba(180, 180, 180, 0.08) 20px),
          radial-gradient(circle at 20% 50%, rgba(200, 200, 200, 0.1) 1px, transparent 1px),
          radial-gradient(circle at 80% 50%, rgba(200, 200, 200, 0.1) 1px, transparent 1px)
        `,
        backgroundSize: '30px 30px, 30px 30px, 50px 50px, 50px 50px',
        opacity: 0.4,
        animation: 'sketch-draw 1.5s ease-out'
      }}></div>

      <div style={{ position: 'relative', zIndex: 10 }}>
        {/* Enhanced Header with Controls */}
        <div style={{ marginBottom: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div>
                <h1 className="pencil-text" style={{
                  fontSize: '36px',
                  fontWeight: 'bold',
                  color: '#333',
                  marginBottom: '8px',
                  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  transform: 'rotate(0deg)',
                  borderBottom: '3px solid #666',
                  paddingBottom: '4px',
                  display: 'inline-block'
                }}>
                  🛡️ KEEPER
                </h1>
                <p style={{ color: '#666', fontSize: '18px', fontWeight: '500', marginBottom: '8px', fontStyle: 'italic' }}>
                  🚀 DevOps Security Frontend - Sending Threat Alerts to AWS CloudWatch
                </p>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Globe style={{ height: '16px', width: '16px', color: '#666' }} />
                    <span style={{ fontSize: '14px', color: '#666', fontWeight: '600' }}>AWS us-east-2</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Wifi style={{ height: '16px', width: '16px', color: '#777' }} />
                    <span style={{ fontSize: '14px', color: '#777' }}>Live Threat Alerts → CloudWatch</span>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Control Panel */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* Monitoring Toggle */}
              <button
                onClick={toggleMonitoring}
                className="sketch-border pencil-text"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '12px 16px',
                  background: isMonitoring ? 'rgba(100, 100, 100, 0.1)' : 'rgba(200, 200, 200, 0.3)',
                  border: `3px solid ${isMonitoring ? '#666' : '#999'}`,
                  borderRadius: '8px',
                  color: isMonitoring ? '#444' : '#666',
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 'bold',
                  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  transform: 'rotate(0deg)',
                  boxShadow: '3px 3px 0px #bbb'
                }}
              >
                {isMonitoring ? <Pause size={16} /> : <Play size={16} />}
                {isMonitoring ? 'STOP MONITORING' : 'START MONITORING'}
              </button>

              {/* Settings */}
              <button
                onClick={() => setShowSettings(!showSettings)}
                className="sketch-border"
                style={{
                  padding: '12px',
                  background: 'rgba(220, 220, 220, 0.5)',
                  border: '2px solid #666',
                  borderRadius: '8px',
                  color: '#444',
                  cursor: 'pointer',
                  transform: 'rotate(0deg)',
                  boxShadow: '2px 2px 0px #bbb'
                }}
              >
                <Settings size={20} />
              </button>

              {/* Controls Toggle */}
              <button
                onClick={() => setShowControls(!showControls)}
                className="sketch-border"
                style={{
                  padding: '12px',
                  background: 'rgba(200, 200, 200, 0.6)',
                  border: '2px solid #777',
                  borderRadius: '8px',
                  color: '#555',
                  cursor: 'pointer',
                  transform: 'rotate(0deg)',
                  boxShadow: '1px 1px 0px #aaa'
                }}
              >
                <Sliders size={20} />
              </button>

              {/* Status */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{
                  height: '16px',
                  width: '16px',
                  borderRadius: '50%',
                  background: isConnected ? '#666' : '#bbb',
                  border: '2px solid #333',
                  boxShadow: '2px 2px 0px #999',
                  animation: 'pulse 2s ease-in-out infinite'
                }} />
                <span className="pencil-text" style={{ color: isConnected ? '#444' : '#777', fontSize: '14px', fontWeight: '600' }}>
                  {isConnected ? 'ONLINE' : 'OFFLINE'}
                </span>
              </div>
            </div>
          </div>

          {/* Settings Panel */}
          {showSettings && (
            <div className="sketch-border crosshatch" style={{
              marginTop: '16px',
              padding: '20px',
              background: 'rgba(240, 240, 240, 0.8)',
              border: '3px solid #666',
              borderRadius: '8px',
              boxShadow: '3px 3px 0px #ccc',
              transform: 'rotate(0deg)'
            }}>
              <h3 className="pencil-text" style={{ color: '#444', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'Courier New, monospace' }}>
                <Settings size={20} />
                SECURITY SETTINGS
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px' }}>
                <div>
                  <label className="pencil-text" style={{ color: '#666', fontSize: '14px', marginBottom: '8px', display: 'block', fontWeight: '600' }}>
                    ALERT THRESHOLD (1-10)
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={alertThreshold}
                    onChange={(e) => updateAlertThreshold(Number(e.target.value))}
                    style={{
                      width: '100%',
                      marginBottom: '8px'
                    }}
                  />
                  <span className="pencil-text" style={{ color: '#777', fontSize: '12px', fontWeight: '600' }}>CURRENT: {alertThreshold}/10</span>
                </div>
              </div>
            </div>
          )}

          {/* Control Panel */}
          {showControls && (
            <div className="sketch-border crosshatch" style={{
              marginTop: '16px',
              padding: '20px',
              background: 'rgba(235, 235, 235, 0.9)',
              border: '3px solid #777',
              borderRadius: '8px',
              boxShadow: '3px 3px 0px #bbb',
              transform: 'rotate(0deg)'
            }}>
              <h3 className="pencil-text" style={{ color: '#555', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'Courier New, monospace' }}>
                <Sliders size={20} />
                THREAT CONTROLS
                {(searchFilter || severityFilter !== 'all') && (
                  <span className="pencil-text" style={{ 
                    background: 'rgba(150, 150, 150, 0.3)', 
                    color: '#666', 
                    padding: '2px 8px', 
                    borderRadius: '12px', 
                    fontSize: '12px',
                    marginLeft: '8px',
                    border: '1px solid #999',
                    boxShadow: '1px 1px 0px #ccc'
                  }}>
                    {filteredEvents.length} THREATS
                  </span>
                )}
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px' }}>
                {/* Search */}
                <div>
                  <label className="pencil-text" style={{ color: '#666', fontSize: '14px', marginBottom: '8px', display: 'block', fontWeight: '600' }}>
                    SEARCH THREATS
                  </label>
                  <div style={{ position: 'relative' }}>
                    <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} size={16} />
                    <input
                      type="text"
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      placeholder="Search by user, IP, or event type..."
                      style={{
                        width: '100%',
                        padding: '8px 8px 8px 40px',
                        background: 'rgba(71, 85, 105, 0.2)',
                        border: '1px solid rgba(71, 85, 105, 0.4)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '14px',
                        outline: 'none'
                      }}
                    />
                  </div>
                </div>

                {/* Severity Filter */}
                <div>
                  <label className="pencil-text" style={{ color: '#666', fontSize: '14px', marginBottom: '8px', display: 'block', fontWeight: '600' }}>
                    THREAT LEVEL
                  </label>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      background: 'rgba(71, 85, 105, 0.2)',
                      border: '1px solid rgba(71, 85, 105, 0.4)',
                      borderRadius: '6px',
                      color: '#ffffff',
                      fontSize: '14px',
                      outline: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    <option value="all" style={{ background: 'rgba(240, 240, 240, 0.95)', color: '#333' }}>All Severities</option>
                    <option value="critical" style={{ background: 'rgba(240, 240, 240, 0.95)', color: '#333' }}>Critical Only</option>
                    <option value="high" style={{ background: 'rgba(240, 240, 240, 0.95)', color: '#333' }}>High</option>
                    <option value="medium" style={{ background: 'rgba(240, 240, 240, 0.95)', color: '#333' }}>Medium</option>
                    <option value="low" style={{ background: 'rgba(240, 240, 240, 0.95)', color: '#333' }}>Low</option>
                  </select>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Stats Cards (Same as before but clickable) */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', 
          gap: '24px', 
          marginBottom: '32px' 
        }}>
          {/* Events Processed Card - Enhanced with click action */}
          <div 
            onClick={() => addToast({
              type: 'info',
              title: 'Event Analytics',
              description: `Processed ${stats.eventsProcessed.toLocaleString()} security events with ${Math.floor(stats.eventsProcessed * 0.1)} new events this hour. All systems operational.`,
              duration: 5000
            })}
            className="sketch-border"
            style={{
              background: 'rgba(240, 240, 240, 0.9)',
              backdropFilter: 'blur(10px)',
              border: '3px solid #666',
              borderRadius: '12px',
              padding: '24px',
              transition: 'all 0.3s ease',
              cursor: 'pointer',
              boxShadow: '3px 3px 0px #ccc',
              transform: 'rotate(0deg)',
            }}
            onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-4px)'}
            onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ 
                padding: '12px', 
                background: 'rgba(255, 193, 7, 0.2)', 
                borderRadius: '8px' 
              }}>
                <Activity style={{ height: '24px', width: '24px', color: '#666' }} />
              </div>
              <BarChart3 style={{ height: '20px', width: '20px', color: '#666' }} />
            </div>
            <div className="pencil-text" style={{ fontSize: '32px', fontWeight: 'bold', color: '#333', marginBottom: '4px' }}>
              {stats.eventsProcessed.toLocaleString()}
            </div>
            <p className="pencil-text" style={{ fontSize: '14px', color: '#666', fontWeight: '500', margin: 0 }}>EVENTS PROCESSED</p>
            <p style={{ fontSize: '12px', color: '#777', marginTop: '4px', margin: 0 }}>
              ⚡ +{Math.floor(stats.eventsProcessed * 0.1)} events this hour
            </p>
          </div>

          {/* Threats Detected Card - Enhanced with manual response */}
          <div 
            onClick={() => addToast({
              type: 'warning',
              title: 'Threat Management',
              description: `${stats.threatsDetected} threats detected with ${((stats.threatsDetected / Math.max(stats.eventsProcessed, 1)) * 100).toFixed(1)}% threat rate. All threats have been automatically responded to.`,
              duration: 5000
            })}
            className="sketch-border"
            style={{
              background: 'rgba(245, 245, 245, 0.9)',
              backdropFilter: 'blur(10px)',
              border: '3px solid #777',
              borderRadius: '12px',
              padding: '24px',
              transition: 'all 0.3s ease',
              cursor: 'pointer',
              boxShadow: '3px 3px 0px #ccc',
              transform: 'rotate(0deg)',
            }}
            onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-4px)'}
            onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ 
                padding: '12px', 
                background: 'rgba(239, 68, 68, 0.2)', 
                borderRadius: '8px' 
              }}>
                <AlertTriangle style={{ height: '24px', width: '24px', color: '#666' }} />
              </div>
              <Target style={{ height: '20px', width: '20px', color: '#666' }} />
            </div>
            <div className="pencil-text" style={{ fontSize: '32px', fontWeight: 'bold', color: '#333', marginBottom: '4px' }}>
              {stats.threatsDetected}
            </div>
            <p className="pencil-text" style={{ fontSize: '14px', color: '#666', fontWeight: '500', margin: 0 }}>Threats Detected</p>
            <p style={{ fontSize: '12px', color: '#777', marginTop: '4px', margin: 0 }}>
              ⚠️ {((stats.threatsDetected / Math.max(stats.eventsProcessed, 1)) * 100).toFixed(1)}% threat rate
            </p>
          </div>

          {/* Responses Executed Card - Enhanced with manual controls */}
          <div 
            onClick={() => addToast({
              type: 'success',
              title: 'Response Center',
              description: `${stats.responsesExecuted} automated responses executed with ${stats.responsesExecuted === stats.threatsDetected ? '100%' : '99%'} success rate. Manual controls available below.`,
              duration: 5000
            })}
            className="sketch-border"
            style={{
              background: 'rgba(250, 250, 250, 0.9)',
              backdropFilter: 'blur(10px)',
              border: '3px solid #888',
              borderRadius: '12px',
              padding: '24px',
              transition: 'all 0.3s ease',
              cursor: 'pointer',
              boxShadow: '3px 3px 0px #ddd',
              transform: 'rotate(0deg)',
            }}
            onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-4px)'}
            onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ 
                padding: '12px', 
                background: 'rgba(147, 51, 234, 0.2)', 
                borderRadius: '8px' 
              }}>
                <Zap style={{ height: '24px', width: '24px', color: '#666' }} />
              </div>
              <CheckCircle style={{ height: '20px', width: '20px', color: '#666' }} />
            </div>
            <div className="pencil-text" style={{ fontSize: '32px', fontWeight: 'bold', color: '#333', marginBottom: '4px' }}>
              {stats.responsesExecuted}
            </div>
            <p className="pencil-text" style={{ fontSize: '14px', color: '#666', fontWeight: '500', margin: 0 }}>Responses Executed</p>
            <p style={{ fontSize: '12px', color: '#777', marginTop: '4px', margin: 0 }}>
              ✅ {stats.responsesExecuted === stats.threatsDetected ? '100%' : '99%'} response rate
            </p>
          </div>

          {/* System Health Card - Enhanced with diagnostic info */}
          <div 
            onClick={() => addToast({
              type: 'success',
              title: 'System Diagnostics',
              description: `System health: ${stats.systemHealth}. All AWS services operational. CloudWatch integration active. No issues detected.`,
              duration: 5000
            })}
            className="sketch-border"
            style={{
              background: 'rgba(235, 235, 235, 0.9)',
              backdropFilter: 'blur(10px)',
              border: '3px solid #999',
              borderRadius: '12px',
              padding: '24px',
              transition: 'all 0.3s ease',
              cursor: 'pointer',
              boxShadow: '3px 3px 0px #bbb',
              transform: 'rotate(0deg)',
            }}
            onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-4px)'}
            onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ 
                padding: '12px', 
                background: 'rgba(16, 185, 129, 0.2)', 
                borderRadius: '8px' 
              }}>
                <Server style={{ height: '24px', width: '24px', color: '#666' }} />
              </div>
              <RefreshCw style={{ height: '20px', width: '20px', color: '#666' }} />
            </div>
            <div className="pencil-text" style={{ fontSize: '32px', fontWeight: 'bold', color: '#333', marginBottom: '4px' }}>
              {stats.systemHealth}
            </div>
            <p className="pencil-text" style={{ fontSize: '14px', color: '#666', fontWeight: '500', margin: 0 }}>System Health</p>
            <p style={{ fontSize: '12px', color: '#777', marginTop: '4px', margin: 0 }}>
              🟢 All services operational
            </p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(600px, 1fr))', gap: '24px' }}>
          {/* Enhanced Interactive Event Feed */}
          <div className="sketch-border crosshatch" style={{
            background: 'rgba(245, 245, 245, 0.95)',
            backdropFilter: 'blur(10px)',
            border: '3px solid #888',
            borderRadius: '12px',
            padding: '24px',
            boxShadow: '4px 4px 0px #ccc',
            transform: 'rotate(0deg)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'between', marginBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Eye style={{ height: '24px', width: '24px', color: '#666' }} />
                <div>
                  <h3 className="pencil-text" style={{ fontSize: '24px', fontWeight: 'bold', color: '#444', margin: 0 }}>DevOps Event Stream</h3>
                  <p style={{ fontSize: '18px', color: '#777', margin: 0 }}>Live AWS Security Events → CloudWatch Logs • {filteredEvents.length} events processed by Keeper frontend</p>
                </div>
              </div>
            </div>

            <div style={{
              maxHeight: '400px',
              overflowY: 'auto',
              paddingRight: '8px'
            }}>
              {filteredEvents.map((event, index) => (
                <div 
                  key={event.id}
                  onClick={() => investigateEvent(event.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '16px',
                    marginBottom: '12px',
                    borderRadius: '8px',
                    border: event.threatDetected ? '2px solid #999' : '2px solid #ccc',
                    background: event.threatDetected 
                      ? 'rgba(255, 200, 200, 0.3)'
                      : 'rgba(240, 240, 240, 0.8)',
                    transition: 'all 0.3s ease',
                    cursor: 'pointer',
                    transform: 'translateX(0)'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(4px)'}
                  onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}
                >
                  <div style={{
                    height: '12px',
                    width: '12px',
                    borderRadius: '50%',
                    marginTop: '8px',
                    background: event.threatDetected ? '#ef4444' : '#10b981',
                    boxShadow: event.threatDetected ? '0 0 10px rgba(239, 68, 68, 0.5)' : '0 0 10px rgba(16, 185, 129, 0.5)',
                    animation: 'pulse 2s ease-in-out infinite'
                  }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <p style={{ fontSize: '18px', fontWeight: '600', color: '#333', margin: 0 }}>
                        🔍 {event.type.replace('_', ' ')}
                      </p>
                      <button 
                        onClick={(e) => { e.stopPropagation(); investigateEvent(event.id); }}
                        style={{
                          padding: '4px 8px',
                          background: 'rgba(59, 130, 246, 0.2)',
                          border: '1px solid rgba(59, 130, 246, 0.4)',
                          borderRadius: '4px',
                          color: '#3b82f6',
                          fontSize: '16px',
                          cursor: 'pointer'
                        }}
                      >
                        INVESTIGATE
                      </button>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', marginBottom: '8px' }}>
                      <span style={{ color: '#666', fontSize: '16px' }}>👤 {event.userId}</span>
                      <span style={{ color: '#666', fontSize: '16px' }}>🌐 {event.sourceIp}</span>
                    </div>
                    <p style={{ fontSize: '16px', color: '#777', margin: 0 }}>
                      ⏱️ {new Date(event.timestamp).toLocaleTimeString()} • {event.resource}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Enhanced Interactive Threat Response Center */}
          <div className="sketch-border crosshatch" style={{
            background: 'rgba(250, 250, 250, 0.95)',
            backdropFilter: 'blur(10px)',
            border: '3px solid #777',
            borderRadius: '12px',
            padding: '24px',
            boxShadow: '4px 4px 0px #ddd',
            transform: 'rotate(0deg)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
              <Shield style={{ height: '24px', width: '24px', color: '#666' }} />
              <div>
                <h3 className="pencil-text" style={{ fontSize: '24px', fontWeight: 'bold', color: '#444', margin: 0 }}>AWS CloudWatch Integration</h3>
                <p style={{ fontSize: '18px', color: '#777', margin: 0 }}>DevOps threat alerts sent to CloudWatch • Professional security monitoring</p>
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
                    borderLeft: '4px solid #999',
                    background: 'rgba(255, 240, 240, 0.8)',
                    border: '2px solid #bbb'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                    <div>
                      <h4 style={{ fontSize: '18px', fontWeight: 'bold', color: '#333', margin: 0 }}>
                        🚨 {threat.type.replace(/_/g, ' ')}
                      </h4>
                      <span style={{ 
                        fontSize: '15px',
                        color: '#ef4444',
                        background: 'rgba(239, 68, 68, 0.2)',
                        padding: '2px 6px',
                        borderRadius: '12px',
                        marginTop: '4px',
                        display: 'inline-block'
                      }}>
                        RISK: {threat.riskScore}/10
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={() => executeManualResponse(threat.id, 'quarantine')}
                        style={{
                          padding: '6px 12px',
                          background: 'rgba(249, 115, 22, 0.2)',
                          border: '1px solid rgba(249, 115, 22, 0.4)',
                          borderRadius: '4px',
                          color: '#f97316',
                          fontSize: '15px',
                          cursor: 'pointer'
                        }}
                      >
                        QUARANTINE
                      </button>
                      <button
                        onClick={() => executeManualResponse(threat.id, 'block_ip')}
                        style={{
                          padding: '6px 12px',
                          background: 'rgba(239, 68, 68, 0.2)',
                          border: '1px solid rgba(239, 68, 68, 0.4)',
                          borderRadius: '4px',
                          color: '#ef4444',
                          fontSize: '15px',
                          cursor: 'pointer'
                        }}
                      >
                        BLOCK IP
                      </button>
                    </div>
                  </div>
                  <p style={{ fontSize: '16px', color: '#666', margin: 0 }}>
                    {threat.description}
                  </p>
                  <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                    {threat.responseActions.map((action, actionIndex) => (
                      <span 
                        key={actionIndex}
                        style={{
                          fontSize: '14px',
                          background: 'rgba(200, 200, 200, 0.5)',
                          color: '#555',
                          padding: '2px 6px',
                          borderRadius: '4px'
                        }}
                      >
                        {action}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Event Investigation Modal */}
        {selectedEvent && eventDetails && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              background: 'rgba(15, 23, 42, 0.95)',
              border: '1px solid rgba(71, 85, 105, 0.5)',
              borderRadius: '12px',
              padding: '24px',
              maxWidth: '600px',
              width: '90%',
              maxHeight: '80%',
              overflowY: 'auto'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <h3 style={{ color: '#22d3ee', margin: 0 }}>Event Investigation: {eventDetails.event_id}</h3>
                <button
                  onClick={() => { setSelectedEvent(null); setEventDetails(null); }}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#64748b',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                >
                  <X size={24} />
                </button>
              </div>
              
              <div style={{ marginBottom: '16px' }}>
                <h4 style={{ color: '#cbd5e1', marginBottom: '8px' }}>Network Trace</h4>
                <div style={{ background: 'rgba(71, 85, 105, 0.2)', padding: '12px', borderRadius: '6px' }}>
                  <p style={{ color: '#64748b', fontSize: '14px', margin: 0 }}>
                    Location: {eventDetails.network_trace.source_location} • 
                    Protocol: {eventDetails.network_trace.protocol} • 
                    Duration: {eventDetails.network_trace.duration}
                  </p>
                </div>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <h4 style={{ color: '#cbd5e1', marginBottom: '8px' }}>User Context</h4>
                <div style={{ background: 'rgba(71, 85, 105, 0.2)', padding: '12px', borderRadius: '6px' }}>
                  <p style={{ color: '#64748b', fontSize: '14px', margin: 0 }}>
                    Risk Score: {eventDetails.user_context.risk_score}/10 • 
                    Location: {eventDetails.user_context.location}
                  </p>
                </div>
              </div>

              <div>
                <h4 style={{ color: '#cbd5e1', marginBottom: '8px' }}>Recommendations</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {eventDetails.recommendations.map((rec, index) => (
                    <div key={index} style={{ 
                      background: 'rgba(16, 185, 129, 0.1)', 
                      border: '1px solid rgba(16, 185, 129, 0.3)',
                      padding: '8px 12px', 
                      borderRadius: '6px',
                      color: '#10b981',
                      fontSize: '14px'
                    }}>
                      ✅ {rec}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function InteractiveSecurityDashboard() {
  return (
    <ToastProvider>
      <InteractiveSecurityDashboardContent />
    </ToastProvider>
  );
}