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
    let recentConnections = [];

    // 从服务器获取SSH连接记录
    function fetchSSHConnections() {
        fetch('/api/ssh-connections')
            .then(response => {
                if (!response.ok) {
                    throw new Error('获取连接记录失败');
                }
                return response.json();
            })
            .then(data => {
                recentConnections = data;
                initRecentConnections();
            })
            .catch(error => {
                console.error('获取SSH连接记录失败:', error);
                // 如果API失败，尝试使用本地存储的备份
                recentConnections = JSON.parse(localStorage.getItem('recentConnections')) || [];
                initRecentConnections();
            });
    }

    // 初始化最近连接列表
    function initRecentConnections() {
        recentConnectionsList.innerHTML = '';
        
        if (recentConnections.length === 0) {
            recentConnectionsList.innerHTML = '<div class="no-connections">暂无连接历史</div>';
            return;
        }
        
        recentConnections.forEach((conn) => {
            const item = document.createElement('div');
            item.className = 'connection-item';
            item.innerHTML = `
                <div class="connection-item-host">${conn.username}@${conn.host}</div>
                <div class="connection-item-details">端口: ${conn.port} | 认证: ${conn.authType === 'password' ? '密码' : 'SSH密钥'}</div>
                <button class="delete-connection" data-id="${conn.id}" title="删除此连接"><i class="fas fa-times"></i></button>
            `;
            
            // 点击连接项填充表单
            item.addEventListener('click', (e) => {
                // 如果点击的是删除按钮，不填充表单
                if (e.target.closest('.delete-connection')) {
                    return;
                }
                
                document.getElementById('host').value = conn.host;
                document.getElementById('port').value = conn.port;
                document.getElementById('username').value = conn.username;
                authTypeSelect.value = conn.authType;
                
                // 触发认证方式变更事件
                const event = new Event('change');
                authTypeSelect.dispatchEvent(event);
            });
            
            // 删除按钮事件
            const deleteBtn = item.querySelector('.delete-connection');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation(); // 阻止事件冒泡
                    const id = deleteBtn.getAttribute('data-id');
                    if (id && id !== 'undefined') {
                        deleteSSHConnection(id);
                    } else {
                        console.error('无效的连接ID');
                        alert('无法删除连接：无效的连接ID');
                    }
                });
            }
            
            recentConnectionsList.appendChild(item);
        });
    }
    
    // 删除SSH连接记录
    function deleteSSHConnection(id) {
        console.log('正在删除连接ID:', id);
        fetch(`/api/ssh-connections/delete?id=${id}`)
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(`删除失败: ${response.status} ${response.statusText} - ${text}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log('删除成功:', data);
                // 删除成功，重新获取连接记录
                fetchSSHConnections();
            })
            .catch(error => {
                console.error('删除SSH连接记录失败:', error);
                alert(`删除连接记录失败: ${error.message}`);
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

    // 保存连接到服务器
    function saveConnection(conn) {
        // 保存到本地存储作为备份
        let localConnections = JSON.parse(localStorage.getItem('recentConnections')) || [];
        
        // 检查是否已存在相同连接
        const existingIndex = localConnections.findIndex(c => 
            c.host === conn.host && 
            c.port === conn.port && 
            c.username === conn.username
        );
        
        // 如果存在，先移除
        if (existingIndex !== -1) {
            localConnections.splice(existingIndex, 1);
        }
        
        // 添加到列表开头
        localConnections.unshift(conn);
        
        // 限制最多保存10个连接
        if (localConnections.length > 10) {
            localConnections.pop();
        }
        
        // 保存到本地存储
        localStorage.setItem('recentConnections', JSON.stringify(localConnections));
        
        // 保存到服务器
        fetch('/api/ssh-connections/save', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                host: conn.host,
                port: conn.port,
                username: conn.username,
                authType: conn.authType
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('保存连接记录失败');
            }
            // 保存成功后重新获取连接列表
            fetchSSHConnections();
        })
        .catch(error => {
            console.error('保存SSH连接记录失败:', error);
            // 如果API失败，至少更新本地UI
            recentConnections = localConnections;
            initRecentConnections();
        });
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
    
    // 获取并初始化最近连接列表
    fetchSSHConnections();
});