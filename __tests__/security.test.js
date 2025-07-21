const request = require('supertest');
const app = require('../app');

describe('Security Tests', () => {
  test('Should register user with valid data', async () => {
    const userData = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'securepassword123'
    };

    const response = await request(app)
      .post('/register')
      .send(userData);

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('id');
    expect(response.body.email).toBe(userData.email);
    expect(response.body).not.toHaveProperty('password');
  });

  test('Should reject weak passwords', async () => {
    const userData = {
      username: 'testuser2',
      email: 'test2@example.com',
      password: '123'
    };

    const response = await request(app)
      .post('/register')
      .send(userData);

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('at least 8 characters');
  });

  test('Should reject invalid email', async () => {
    const userData = {
      username: 'testuser3',
      email: 'invalid-email',
      password: 'securepassword123'
    };

    const response = await request(app)
      .post('/register')
      .send(userData);

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Invalid email');
  });

  test('Should login with valid credentials', async () => {
    // まずユーザーを登録
    await request(app)
      .post('/register')
      .send({
        username: 'logintest',
        email: 'login@example.com',
        password: 'securepassword123'
      });

    // ログインテスト
    const response = await request(app)
      .post('/login')
      .send({
        email: 'login@example.com',
        password: 'securepassword123'
      });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('token');
    expect(response.body).toHaveProperty('userId');
  });

  test('Should reject invalid login credentials', async () => {
    const response = await request(app)
      .post('/login')
      .send({
        email: 'nonexistent@example.com',
        password: 'wrongpassword'
      });

    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Invalid credentials');
  });

  test('Should protect profile endpoint', async () => {
    const response = await request(app).get('/profile');
    
    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Access token required');
  });

  test('Health check should work', async () => {
    const response = await request(app).get('/health');
    
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('healthy');
  });
});
