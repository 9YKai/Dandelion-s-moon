const express = require('express');      // 导入Express框架
const cors = require('cors');            // 解决跨域问题
const mysql = require('mysql2/promise'); // 使用Promise版本的mysql2库
const bcrypt = require('bcrypt');        // 用于密码加密
const jwt = require('jsonwebtoken');     // 用于生成和验证登录令牌
require('dotenv').config();              // 用于加载环境变量

const app = express();
const PORT = process.env.PORT || 3010;

// --- 1. 中间件配置 ------------------------------------------------
// 解析JSON格式的请求体
app.use(express.json()); 
// 允许所有域名访问我们的API（开发环境用）
app.use(cors());        

// --- 2. 数据库连接池配置 --------------------------------------------
// 创建一个连接池，高效地管理数据库连接
// ⚠️ 重要：请根据你的实际MySQL配置，修改下面的password
const db = mysql.createPool({
    host: 'localhost',   // 数据库地址，本地开发就是localhost
    user: 'root',        // 数据库用户名，一般是root
    password: '123456',  // 替换为你安装MySQL时设置的root密码
    database: 'dandelion_game', // 我们刚刚创建的数据库名
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// 测试数据库连接
db.getConnection().then(conn => {
    console.log('✅ 数据库连接成功！');
    conn.release();
}).catch(err => {
    console.error('❌ 数据库连接失败:', err.message);
});

// --- 3. 工具函数 ---------------------------------------------------
// 一个验证JWT Token的中间件，用于保护需要登录才能访问的接口
const authenticateToken = (req, res, next) => {
    // 从请求头中获取Authorization字段
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // 格式: "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: '未提供认证令牌' });
    }

    // 验证Token的有效性
    jwt.verify(token, process.env.SECRET_KEY || '12345678', (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: '令牌无效或已过期' });
        }
        // Token验证通过，将用户信息挂载到请求对象上，供后续处理使用
        req.user = user;
        next();
    });
};

// --- 4. API接口（和后端交互的地方）--------------------------------------
// 接口1：用户注册
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // 检查用户名是否已存在
        const [existingUsers] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: '用户名已被占用' });
        }
        // 对密码进行加密，加盐轮次设为10
        const hashedPassword = await bcrypt.hash(password, 10);
        // 将新用户信息存入数据库
        const [result] = await db.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword]);
        
        // 创建初始存档
        const initialSaveData = JSON.stringify({
            unlockedLevels: [1],
            completedLevels: [],
            hasFirefly: false,
            maxLives: 3,
            lastScene: 'Loading',
            lastPosition: { x: 0, y: 0, z: 0 }
        });
        
        await db.query('INSERT INTO saves (user_id, save_data) VALUES (?, ?)', [result.insertId, initialSaveData]);
        
        res.json({ success: true, message: '注册成功！', userId: result.insertId });
    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// 接口2：用户登录
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        // 根据用户名查找用户
        const [users] = await db.query('SELECT id, username, password_hash,signature FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ success: false, message: '用户名或密码错误' });
        }
        const user = users[0];
        // 比对输入的密码和数据库里存储的加密密码
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: '用户名或密码错误' });
        }
        // 登录成功，生成JWT Token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.SECRET_KEY || '12345678',
            { expiresIn: '7d' } // Token有效期为7天
        );
        
        // 获取用户存档
        const [saves] = await db.query('SELECT save_data FROM saves WHERE user_id = ?', [user.id]);
        let gameProgress;
        if (saves.length > 0 && saves[0].save_data) {
            // MySQL 的 json 类型字段会被 mysql2 自动解析为 JavaScript 对象，不需要 JSON.parse()
            gameProgress = saves[0].save_data;
        } else {
            // 默认存档
            gameProgress = 
            {
                unlockedLevels: [],
                completedLevels: [],
                hasFirefly: false,
                maxLives: 3,
                lastScene: 'Loading',
                lastPosition: { x: 0, y: 0, z: 0 }
            };
        }
        
        res.json({ 
            success: true, 
            message: '登录成功！', 
            token, 
            userId: user.id,
            username: user.username,
            gameProgress,
            signature: user.signature
        });
    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});


// 接口3：验证token
app.get('/api/validate', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// 接口4：保存游戏存档（需要登录）
app.post('/api/save', authenticateToken, async (req, res) => {
    try {
        const { saveData } = req.body;
        const userId = req.user.id;
        
        // 先尝试更新现有记录
        const [updateResult] = await db.query(
            'UPDATE saves SET save_data = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
            [JSON.stringify(saveData), userId]
        );
        
        // 如果没有更新任何记录，说明用户还没有存档，插入新记录
        if (updateResult.affectedRows === 0) {
            await db.query(
                'INSERT INTO saves (user_id, save_data) VALUES (?, ?)',
                [userId, JSON.stringify(saveData)]
            );
        }
        
        res.json({ success: true, message: '游戏进度已保存！' });
    } catch (error) {
        console.error('保存存档错误:', error);
        res.status(500).json({ success: false, message: '保存失败，请稍后重试' });
    }
});

// 接口5：读取游戏存档（需要登录）
app.get('/api/load', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const [saves] = await db.query('SELECT save_data FROM saves WHERE user_id = ?', [userId]);
        if (saves.length === 0) {
            const defaultSaveData = {
                unlockedLevels: [1],
                completedLevels: [],
                maxLives: 3,
                lastScene: 'Loading',
                lastPosition: { x: 0, y: 0, z: 0 }
            };
            return res.json({ success: true, saveData: defaultSaveData, message: '没有找到存档，使用默认存档' });
        }
        // MySQL 的 json 类型字段会被 mysql2 自动解析为 JavaScript 对象，不需要 JSON.parse()
        const saveData = saves[0].save_data;
        res.json({ success: true, saveData });
    } catch (error) {
        console.error('读取存档错误:', error);
        res.status(500).json({ success: false, message: '读取存档失败' });
    }
});

// 接口6：获取用户信息（需要登录）
app.get('/api/user/info', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const [users] = await db.query('SELECT id, username, created_at FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: '用户不存在' });
        }
        res.json({ success: true, user: users[0] });
    } catch (error) {
        console.error('获取用户信息错误:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});

// 接口7：注销用户账号（需要登录）
app.post('/api/destroy', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // 先删除用户的存档记录
        await db.query('DELETE FROM saves WHERE user_id = ?', [userId]);
        
        // 再删除用户记录
        await db.query('DELETE FROM users WHERE id = ?', [userId]);
        
        res.json({ success: true, message: '账号注销成功' });
    } catch (error) {
        console.error('注销账号错误:', error);
        res.status(500).json({ success: false, message: '注销失败，请稍后重试' });
    }
});

// 接口8：更新用户信息（用户名或签名）
app.put('/api/user/update', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { username, signature } = req.body;

        // 1. 如果修改用户名，检查唯一性
        if (username !== undefined && username !== null) {
            const [existing] = await db.query(
                'SELECT id FROM users WHERE username = ? AND id != ?',
                [username, userId]
            );
            if (existing.length > 0) {
                return res.status(400).json({ success: false, message: '用户名已被占用' });
            }
            await db.query('UPDATE users SET username = ? WHERE id = ?', [username, userId]);
        }

        // 2. 如果修改签名（确保 users 表有 signature 字段）
        if (signature !== undefined && signature !== null) {
            await db.query('UPDATE users SET signature = ? WHERE id = ?', [signature, userId]);
        }

        res.json({ success: true, message: '更新成功' });
    } catch (error) {
        console.error('更新用户信息错误:', error);
        res.status(500).json({ success: false, message: '服务器内部错误' });
    }
});


// --- 5. 启动服务器 ------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 后端服务已启动，访问地址：http://localhost:${PORT}`);
});
