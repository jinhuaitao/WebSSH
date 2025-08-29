document.addEventListener('DOMContentLoaded', () => {
    // DOM元素
    const loginForm = document.getElementById('login-form');
    const welcomeContainer = document.getElementById('welcome-container');
    const terminalContainer = document.getElementById('terminal-container');
    const terminalElement = document.getElementById('terminal');
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const fullscreenBtn = document.getElementById('fullscreen-btn');
    const themeToggleBtn = document.getElementById('theme-toggle');
    const authTypeSelect = document.getElementById('auth-type');
    const passwordGroup = document.getElementById('password-group');
    const keyGroup = document.getElementById('key-group');
    const connectionInfo = document.getElementById('connection-info');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const passwordInput = document.getElementById('password');
    const sidebar = document.getElementById('sidebar');
    const recentConnectionsList = document.getElementById('recent-connections');

    // 终端实例
    let terminal;
    let fitAddon;
    let socket;
    
    // 最近连接历史
    let recentConnections = JSON.parse(localStorage.getItem('recentConnections')) || [];

    // 初始化最近连接列表
    function initRecentConnections() {
        recentConnectionsList.innerHTML = '';
        
        if (recentConnections.length === 0) {
            recentConnectionsList.innerHTML = '<div class="no-connections">暂无连接历史</div>';
            return;
        }
        
        recentConnections.forEach((conn, index) => {
            const item = document.createElement('div');
            item.className = 'connection-item';
            item.innerHTML = `
                <div class="connection-item-host">${conn.username}@${conn.host}</div>
                <div class="connection-item-details">端口: ${conn.port} | 认证: ${conn.authType === 'password' ? '密码' : 'SSH密钥'}</div>
            `;
            
            item.addEventListener('click', () => {
                document.getElementById('host').value = conn.host;
                document.getElementById('port').value = conn.port;
                document.getElementById('username').value = conn.username;
                authTypeSelect.value = conn.authType;
                
                // 触发认证方式变更事件
                const event = new Event('change');
                authTypeSelect.dispatchEvent(event);
                
                if (conn.authType === 'password' && conn.password) {
                    passwordInput.value = conn.password;
                } else if (conn.authType === 'key' && conn.key) {
                    document.getElementById('key').value = conn.key;
                }
            });
            
            recentConnectionsList.appendChild(item);
        });
    }

    // 切换密码可见性
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', () => {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            togglePasswordBtn.innerHTML = type === 'password' ? 
                '<i class="fas fa-eye"></i>' : 
                '<i class="fas fa-eye-slash"></i>';
        });
    }

    // 侧边栏始终显示
    sidebar.classList.add('show');

    // 切换认证方式
    authTypeSelect.addEventListener('change', () => {
        if (authTypeSelect.value === 'password') {
            passwordGroup.style.display = 'block';
            keyGroup.style.display = 'none';
        } else {
            passwordGroup.style.display = 'none';
            keyGroup.style.display = 'block';
        }
    });

    // 连接按钮点击事件
    connectBtn.addEventListener('click', () => {
        const host = document.getElementById('host').value.trim();
        const port = document.getElementById('port').value.trim();
        const username = document.getElementById('username').value.trim();
        const authType = authTypeSelect.value;
        const password = document.getElementById('password').value;
        const key = document.getElementById('key').value;

        // 验证输入
        if (!host) {
            alert('请输入主机地址');
            return;
        }
        if (!port) {
            alert('请输入端口');
            return;
        }
        if (!username) {
            alert('请输入用户名');
            return;
        }
        if (authType === 'password' && !password) {
            alert('请输入密码');
            return;
        }
        if (authType === 'key' && !key) {
            alert('请输入SSH私钥');
            return;
        }

        // 创建连接配置
        const config = {
            host: host,
            port: port,
            username: username,
            password: authType === 'password' ? password : '',
            key: authType === 'key' ? key : ''
        };

        // 保存到最近连接
        saveConnection({
            host: host,
            port: port,
            username: username,
            authType: authType,
            password: authType === 'password' ? password : '',
            key: authType === 'key' ? key : ''
        });

        // 初始化终端
        initTerminal();

        // 连接WebSocket
        connectWebSocket(config);

        // 显示终端容器
        welcomeContainer.style.display = 'none';
        terminalContainer.style.display = 'flex';
        connectionInfo.textContent = `${username}@${host}:${port}`;

        // 在移动设备上自动隐藏侧边栏
        if (window.innerWidth <= 768) {
            sidebar.classList.remove('show');
        }

        // 调整终端大小
        setTimeout(() => {
            fitAddon.fit();
        }, 100);
    });

    // 断开连接按钮点击事件
    disconnectBtn.addEventListener('click', () => {
        if (socket) {
            socket.close();
        }
        terminalContainer.style.display = 'none';
        welcomeContainer.style.display = 'flex';
        sidebar.classList.add('show');
        terminal.dispose();
    });

    // 保存连接到最近连接列表
    function saveConnection(conn) {
        // 检查是否已存在相同连接
        const existingIndex = recentConnections.findIndex(c => 
            c.host === conn.host && 
            c.port === conn.port && 
            c.username === conn.username
        );
        
        // 如果存在，先移除
        if (existingIndex !== -1) {
            recentConnections.splice(existingIndex, 1);
        }
        
        // 添加到列表开头
        recentConnections.unshift(conn);
        
        // 限制最多保存5个连接
        if (recentConnections.length > 5) {
            recentConnections.pop();
        }
        
        // 保存到本地存储
        localStorage.setItem('recentConnections', JSON.stringify(recentConnections));
        
        // 更新UI
        initRecentConnections();
    }

    // 初始化终端
    function initTerminal() {
        terminal = new Terminal({
            cursorBlink: true,
            theme: {
                background: '#1e1e1e',
                foreground: '#f0f0f0',
                cursor: '#f0f0f0',
                selection: 'rgba(255, 255, 255, 0.3)',
                black: '#000000',
                red: '#e74c3c',
                green: '#2ecc71',
                yellow: '#f1c40f',
                blue: '#3498db',
                magenta: '#9b59b6',
                cyan: '#1abc9c',
                white: '#ecf0f1',
                brightBlack: '#7f8c8d',
                brightRed: '#e74c3c',
                brightGreen: '#2ecc71',
                brightYellow: '#f1c40f',
                brightBlue: '#3498db',
                brightMagenta: '#9b59b6',
                brightCyan: '#1abc9c',
                brightWhite: '#ffffff'
            },
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            fontSize: 14,
            lineHeight: 1.2,
            scrollback: 10000
        });

        fitAddon = new FitAddon.FitAddon();
        terminal.loadAddon(fitAddon);
        terminal.open(terminalElement);
        
        // 监听窗口大小变化
        window.addEventListener('resize', () => {
            fitAddon.fit();
            if (socket && socket.readyState === WebSocket.OPEN) {
                const dimensions = fitAddon.proposeDimensions();
                if (dimensions) {
                    const msg = new Uint8Array(5);
                    msg[0] = 1; // 控制字符
                    msg[1] = dimensions.cols >> 8;
                    msg[2] = dimensions.cols & 0xff;
                    msg[3] = dimensions.rows >> 8;
                    msg[4] = dimensions.rows & 0xff;
                    socket.send(msg);
                }
            }
        });
    }

    // 连接WebSocket
    function connectWebSocket(config) {
        // 确定WebSocket URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ssh`;

        // 创建WebSocket连接
        socket = new WebSocket(wsUrl);

        // 连接建立时发送配置
        socket.onopen = () => {
            socket.send(JSON.stringify(config));
        };

        // 接收服务器消息
        socket.onmessage = (event) => {
            terminal.write(event.data);
        };

        // 连接关闭
        socket.onclose = () => {
            terminal.write('\r\n\x1b[31m连接已关闭\x1b[0m\r\n');
        };

        // 连接错误
        socket.onerror = (error) => {
            console.error('WebSocket错误:', error);
            terminal.write('\r\n\x1b[31m连接错误\x1b[0m\r\n');
        };

        // 终端输入发送到WebSocket
        terminal.onData(data => {
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(data);
            }
        });
    }
    
    // 初始化最近连接列表
    initRecentConnections();
});