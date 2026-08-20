#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  CallToolRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { NodeSSH } from 'node-ssh';
import { z } from 'zod';
import * as fs from 'fs/promises';
import * as path from 'path';
// node-pty removed as it's not used in this implementation
import { EventEmitter } from 'events';
import * as os from 'os';
import * as crypto from 'crypto';
import { createHostVerifier } from './host-key-verify.js';
import { shellQuote, isValidEnvVarName } from './shell-quote.js';

// Connection pool to manage SSH connections
const connectionPool = new Map<string, NodeSSH>();

// Working directory context for each connection
interface ConnectionContext {
  ssh: NodeSSH;
  currentWorkingDirectory?: string;
  defaultWorkingDirectory?: string;
}

const connectionContexts = new Map<string, ConnectionContext>();

// Credential storage interface
interface StoredCredential {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKeyPath?: string;
  passphrase?: string;
  createdAt: string;
  lastUsed: string;
}

// In-memory credential store (could be extended to file-based storage)
const credentialStore = new Map<string, StoredCredential>();

// Interactive shell session pool
interface ShellSession {
  shell: any; // SSH ClientChannel
  ssh: NodeSSH;
  emitter: EventEmitter;
  buffer: string;
  isActive: boolean;
}

const shellSessions = new Map<string, ShellSession>();

// Schema definitions for tool parameters
const ConnectSSHSchema = z.object({
  host: z.string().describe('SSH server hostname or IP address'),
  port: z.number().default(22).describe('SSH port number'),
  username: z.string().describe('SSH username'),
  password: z.string().optional().describe('SSH password (if not using key)'),
  privateKeyPath: z.string().optional().describe('Path to private key file'),
  passphrase: z.string().optional().describe('Passphrase for private key'),
  connectionId: z.string().describe('Unique identifier for this connection')
});

const DisconnectSSHSchema = z.object({
  connectionId: z.string().describe('Connection ID to disconnect')
});

const ExecuteCommandSchema = z.object({
  connectionId: z.string().describe('SSH connection ID'),
  command: z.string().describe('Command to execute on remote server'),
  cwd: z.string().optional().describe('Working directory for command execution')
});

const CopyFileSchema = z.object({
  sourceConnectionId: z.string().describe('Source SSH connection ID (use "local" for local files)'),
  sourcePath: z.string().describe('Source file path'),
  targetConnectionId: z.string().describe('Target SSH connection ID (use "local" for local files)'),
  targetPath: z.string().describe('Target file path'),
  createDirectories: z.boolean().default(true).describe('Create target directories if they don\'t exist')
});

const ListFilesSchema = z.object({
  connectionId: z.string().describe('SSH connection ID (use "local" for local files)'),
  remotePath: z.string().describe('Directory path to list'),
  showHidden: z.boolean().default(false).describe('Show hidden files')
});

const FileInfoSchema = z.object({
  connectionId: z.string().describe('SSH connection ID (use "local" for local files)'),
  filePath: z.string().describe('File path to get info for')
});

const StartInteractiveShellSchema = z.object({
  connectionId: z.string().describe('SSH connection ID'),
  sessionId: z.string().describe('Unique identifier for this interactive session'),
  shell: z.string().default('/bin/bash').describe('Shell to use (e.g., /bin/bash, /bin/zsh)'),
  cols: z.number().default(80).describe('Terminal columns'),
  rows: z.number().default(24).describe('Terminal rows')
});

const SendInputSchema = z.object({
  sessionId: z.string().describe('Interactive session ID'),
  input: z.string().describe('Input to send to the shell'),
  simulateTyping: z.boolean().default(false).describe('Simulate human typing with delays')
});

const ReadOutputSchema = z.object({
  sessionId: z.string().describe('Interactive session ID'),
  timeout: z.number().default(5000).describe('Timeout in milliseconds to wait for output'),
  clearBuffer: z.boolean().default(true).describe('Clear the output buffer after reading')
});

const CloseInteractiveShellSchema = z.object({
  sessionId: z.string().describe('Interactive session ID to close')
});

const SaveCredentialSchema = z.object({
  credentialId: z.string().describe('Unique identifier for this credential'),
  host: z.string().describe('SSH server hostname or IP address'),
  port: z.number().default(22).describe('SSH port number'),
  username: z.string().describe('SSH username'),
  password: z.string().optional().describe('SSH password (if not using key)'),
  privateKeyPath: z.string().optional().describe('Path to private key file'),
  passphrase: z.string().optional().describe('Passphrase for private key')
});

const LoadCredentialSchema = z.object({
  credentialId: z.string().describe('Credential ID to load')
});

const ListCredentialsSchema = z.object({});

const DeleteCredentialSchema = z.object({
  credentialId: z.string().describe('Credential ID to delete')
});

const ConnectWithCredentialSchema = z.object({
  credentialId: z.string().describe('Stored credential ID to use'),
  connectionId: z.string().describe('Unique identifier for this connection')
});

const SetWorkingDirectorySchema = z.object({
  connectionId: z.string().describe('SSH connection ID'),
  workingDirectory: z.string().describe('Working directory path to set as current')
});

const GetWorkingDirectorySchema = z.object({
  connectionId: z.string().describe('SSH connection ID')
});

const DockerDeploySchema = z.object({
  connectionId: z.string().describe('SSH connection ID'),
  workingDirectory: z.string().describe('Directory containing docker-compose.yml or Dockerfile'),
  deploymentType: z.enum(['compose', 'build', 'run']).describe('Type of Docker deployment'),
  imageName: z.string().optional().describe('Docker image name (for build/run)'),
  containerName: z.string().optional().describe('Container name (for run)'),
  composeFile: z.string().default('docker-compose.yml').describe('Docker compose file name'),
  buildArgs: z.record(z.string()).optional().describe('Build arguments for Docker build'),
  envVars: z.record(z.string()).optional().describe('Environment variables'),
  ports: z.array(z.string()).optional().describe('Port mappings (e.g., ["8080:80", "3000:3000"])'),
  volumes: z.array(z.string()).optional().describe('Volume mappings (e.g., ["/host/path:/container/path"])'),
  detached: z.boolean().default(true).describe('Run in detached mode')
});

const DockerStatusSchema = z.object({
  connectionId: z.string().describe('SSH connection ID'),
  workingDirectory: z.string().optional().describe('Working directory to check (defaults to current)')
});

class SSHMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: 'ssh-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private setupErrorHandling(): void {
    this.server.onerror = (error: Error) => {
      console.error('[MCP Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.cleanup();
      process.exit(0);
    });
  }

  private async cleanup(): Promise<void> {
    console.log('Cleaning up SSH connections and shell sessions...');
    
    // Clean up shell sessions
    for (const [sessionId, session] of shellSessions.entries()) {
      try {
        session.shell.close();
        session.isActive = false;
        shellSessions.delete(sessionId);
        console.log(`Closed shell session: ${sessionId}`);
      } catch (error) {
        console.error(`Error closing shell session ${sessionId}:`, error);
      }
    }
    
    // Clean up SSH connections
    for (const [connectionId, ssh] of connectionPool.entries()) {
      try {
        ssh.dispose();
        connectionPool.delete(connectionId);
        console.log(`Disconnected: ${connectionId}`);
      } catch (error) {
        console.error(`Error disconnecting ${connectionId}:`, error);
      }
    }
  }

  private setupToolHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'ssh_connect',
            description: 'Connect to an SSH server',
            inputSchema: {
              type: 'object',
              properties: {
                host: { type: 'string', description: 'SSH server hostname or IP address' },
                port: { type: 'number', default: 22, description: 'SSH port number' },
                username: { type: 'string', description: 'SSH username' },
                password: { type: 'string', description: 'SSH password (if not using key)' },
                privateKeyPath: { type: 'string', description: 'Path to private key file' },
                passphrase: { type: 'string', description: 'Passphrase for private key' },
                connectionId: { type: 'string', description: 'Unique identifier for this connection' }
              },
              required: ['host', 'username', 'connectionId']
            },
          },
          {
            name: 'ssh_disconnect',
            description: 'Disconnect from an SSH server',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'Connection ID to disconnect' }
              },
              required: ['connectionId']
            },
          },
          {
            name: 'ssh_execute',
            description: 'Execute a command on a remote SSH server',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' },
                command: { type: 'string', description: 'Command to execute on remote server' },
                cwd: { type: 'string', description: 'Working directory for command execution' }
              },
              required: ['connectionId', 'command']
            },
          },
          {
            name: 'ssh_copy_file',
            description: 'Copy files between local and remote servers or between remote servers',
            inputSchema: {
              type: 'object',
              properties: {
                sourceConnectionId: { type: 'string', description: 'Source SSH connection ID (use "local" for local files)' },
                sourcePath: { type: 'string', description: 'Source file path' },
                targetConnectionId: { type: 'string', description: 'Target SSH connection ID (use "local" for local files)' },
                targetPath: { type: 'string', description: 'Target file path' },
                createDirectories: { type: 'boolean', default: true, description: 'Create target directories if they don\'t exist' }
              },
              required: ['sourceConnectionId', 'sourcePath', 'targetConnectionId', 'targetPath']
            },
          },
          {
            name: 'ssh_list_files',
            description: 'List files and directories on local or remote server',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID (use "local" for local files)' },
                remotePath: { type: 'string', description: 'Directory path to list' },
                showHidden: { type: 'boolean', default: false, description: 'Show hidden files' }
              },
              required: ['connectionId', 'remotePath']
            },
          },
          {
            name: 'ssh_file_info',
            description: 'Get file information (size, permissions, etc.)',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID (use "local" for local files)' },
                filePath: { type: 'string', description: 'File path to get info for' }
              },
              required: ['connectionId', 'filePath']
            },
          },
          {
            name: 'ssh_start_interactive_shell',
            description: 'Start an interactive shell session with PTY support for typing simulation',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' },
                sessionId: { type: 'string', description: 'Unique identifier for this interactive session' },
                shell: { type: 'string', default: '/bin/bash', description: 'Shell to use (e.g., /bin/bash, /bin/zsh)' },
                cols: { type: 'number', default: 80, description: 'Terminal columns' },
                rows: { type: 'number', default: 24, description: 'Terminal rows' }
              },
              required: ['connectionId', 'sessionId']
            },
          },
          {
            name: 'ssh_send_input',
            description: 'Send input to an interactive shell session with optional typing simulation',
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'Interactive session ID' },
                input: { type: 'string', description: 'Input to send to the shell' },
                simulateTyping: { type: 'boolean', default: false, description: 'Simulate human typing with delays' }
              },
              required: ['sessionId', 'input']
            },
          },
          {
            name: 'ssh_read_output',
            description: 'Read output from an interactive shell session',
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'Interactive session ID' },
                timeout: { type: 'number', default: 5000, description: 'Timeout in milliseconds to wait for output' },
                clearBuffer: { type: 'boolean', default: true, description: 'Clear the output buffer after reading' }
              },
              required: ['sessionId']
            },
          },
          {
            name: 'ssh_close_interactive_shell',
            description: 'Close an interactive shell session',
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'Interactive session ID to close' }
              },
              required: ['sessionId']
            },
          },
          {
            name: 'ssh_save_credential',
            description: 'Save SSH credentials for reuse',
            inputSchema: {
              type: 'object',
              properties: {
                credentialId: { type: 'string', description: 'Unique identifier for this credential' },
                host: { type: 'string', description: 'SSH server hostname or IP address' },
                port: { type: 'number', default: 22, description: 'SSH port number' },
                username: { type: 'string', description: 'SSH username' },
                password: { type: 'string', description: 'SSH password (if not using key)' },
                privateKeyPath: { type: 'string', description: 'Path to private key file' },
                passphrase: { type: 'string', description: 'Passphrase for private key' }
              },
              required: ['credentialId', 'host', 'username']
            },
          },
          {
            name: 'ssh_list_credentials',
            description: 'List all saved SSH credentials',
            inputSchema: {
              type: 'object',
              properties: {},
              required: []
            },
          },
          {
            name: 'ssh_delete_credential',
            description: 'Delete a saved SSH credential',
            inputSchema: {
              type: 'object',
              properties: {
                credentialId: { type: 'string', description: 'Credential ID to delete' }
              },
              required: ['credentialId']
            },
          },
          {
            name: 'ssh_connect_with_credential',
            description: 'Connect to SSH server using saved credentials',
            inputSchema: {
              type: 'object',
              properties: {
                credentialId: { type: 'string', description: 'Stored credential ID to use' },
                connectionId: { type: 'string', description: 'Unique identifier for this connection' }
              },
              required: ['credentialId', 'connectionId']
            },
          },
          {
            name: 'ssh_set_working_directory',
            description: 'Set the current working directory for a connection',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' },
                workingDirectory: { type: 'string', description: 'Working directory path to set as current' }
              },
              required: ['connectionId', 'workingDirectory']
            },
          },
          {
            name: 'ssh_get_working_directory',
            description: 'Get the current working directory for a connection',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' }
              },
              required: ['connectionId']
            },
          },
          {
            name: 'ssh_docker_deploy',
            description: 'Deploy Docker containers with working directory context',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' },
                workingDirectory: { type: 'string', description: 'Directory containing docker-compose.yml or Dockerfile' },
                deploymentType: { type: 'string', enum: ['compose', 'build', 'run'], description: 'Type of Docker deployment' },
                imageName: { type: 'string', description: 'Docker image name (for build/run)' },
                containerName: { type: 'string', description: 'Container name (for run)' },
                composeFile: { type: 'string', default: 'docker-compose.yml', description: 'Docker compose file name' },
                buildArgs: { type: 'object', description: 'Build arguments for Docker build' },
                envVars: { type: 'object', description: 'Environment variables' },
                ports: { type: 'array', items: { type: 'string' }, description: 'Port mappings (e.g., ["8080:80", "3000:3000"])' },
                volumes: { type: 'array', items: { type: 'string' }, description: 'Volume mappings (e.g., ["/host/path:/container/path"])' },
                detached: { type: 'boolean', default: true, description: 'Run in detached mode' }
              },
              required: ['connectionId', 'workingDirectory', 'deploymentType']
            },
          },
          {
            name: 'ssh_docker_status',
            description: 'Check Docker container status in working directory',
            inputSchema: {
              type: 'object',
              properties: {
                connectionId: { type: 'string', description: 'SSH connection ID' },
                workingDirectory: { type: 'string', description: 'Working directory to check (defaults to current)' }
              },
              required: ['connectionId']
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
      try {
        const { name, arguments: args } = request.params;

        switch (name) {
          case 'ssh_connect':
            return await this.handleSSHConnect(args);
          case 'ssh_disconnect':
            return await this.handleSSHDisconnect(args);
          case 'ssh_execute':
            return await this.handleSSHExecute(args);
          case 'ssh_copy_file':
            return await this.handleSSHCopyFile(args);
          case 'ssh_list_files':
            return await this.handleSSHListFiles(args);
          case 'ssh_file_info':
            return await this.handleSSHFileInfo(args);
          case 'ssh_start_interactive_shell':
            return await this.handleStartInteractiveShell(args);
          case 'ssh_send_input':
            return await this.handleSendInput(args);
          case 'ssh_read_output':
            return await this.handleReadOutput(args);
          case 'ssh_close_interactive_shell':
            return await this.handleCloseInteractiveShell(args);
          case 'ssh_save_credential':
            return await this.handleSaveCredential(args);
          case 'ssh_list_credentials':
            return await this.handleListCredentials(args);
          case 'ssh_delete_credential':
            return await this.handleDeleteCredential(args);
          case 'ssh_connect_with_credential':
            return await this.handleConnectWithCredential(args);
          case 'ssh_set_working_directory':
            return await this.handleSetWorkingDirectory(args);
          case 'ssh_get_working_directory':
            return await this.handleGetWorkingDirectory(args);
          case 'ssh_docker_deploy':
            return await this.handleDockerDeploy(args);
          case 'ssh_docker_status':
            return await this.handleDockerStatus(args);
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    });
  }

  private async handleSSHConnect(args: unknown) {
    const params = ConnectSSHSchema.parse(args);
    
    if (connectionPool.has(params.connectionId)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' already exists`
      );
    }

    const ssh = new NodeSSH();
    
    // Host key verification against known_hosts (fail closed; see src/host-key-verify.ts)
    const hostKeyCheck = createHostVerifier(params.host, params.port);

    try {
      const connectConfig: any = {
        host: params.host,
        port: params.port,
        username: params.username,
        hostVerifier: hostKeyCheck.hostVerifier,
      };

      if (params.privateKeyPath) {
        const privateKey = await fs.readFile(params.privateKeyPath, 'utf8');
        connectConfig.privateKey = privateKey;
        if (params.passphrase) {
          connectConfig.passphrase = params.passphrase;
        }
      } else if (params.password) {
        connectConfig.password = params.password;
      } else {
        throw new McpError(
          ErrorCode.InvalidParams,
          'Either password or privateKeyPath must be provided'
        );
      }

      await ssh.connect(connectConfig);
      connectionPool.set(params.connectionId, ssh);
      
      // Initialize connection context
      connectionContexts.set(params.connectionId, {
        ssh,
        currentWorkingDirectory: undefined,
        defaultWorkingDirectory: undefined
      });

      return {
        content: [
          {
            type: 'text',
            text: `Successfully connected to ${params.host}:${params.port} as ${params.username} (Connection ID: ${params.connectionId})`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `SSH connection failed: ${hostKeyCheck.lastFailure() ?? (error instanceof Error ? error.message : String(error))}`
      );
    }
  }

  private async handleSSHDisconnect(args: unknown) {
    const params = DisconnectSSHSchema.parse(args);
    
    const ssh = connectionPool.get(params.connectionId);
    if (!ssh) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    ssh.dispose();
    connectionPool.delete(params.connectionId);
    
    // Clean up connection context
    connectionContexts.delete(params.connectionId);

    return {
      content: [
        {
          type: 'text',
          text: `Disconnected from ${params.connectionId}`,
        },
      ],
    };
  }

  private async handleSSHExecute(args: unknown) {
    const params = ExecuteCommandSchema.parse(args);
    
    const ssh = connectionPool.get(params.connectionId);
    if (!ssh) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    try {
      const result = await ssh.execCommand(params.command, {
        cwd: params.cwd,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Command: ${params.command}\nExit Code: ${result.code}\n\nSTDOUT:\n${result.stdout}\n\nSTDERR:\n${result.stderr}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Command execution failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleSSHCopyFile(args: unknown) {
    const params = CopyFileSchema.parse(args);
    
    try {
      // Handle different copy scenarios
      if (params.sourceConnectionId === 'local' && params.targetConnectionId === 'local') {
        // Local to local copy
        await fs.copyFile(params.sourcePath, params.targetPath);
        return {
          content: [
            {
              type: 'text',
              text: `Successfully copied ${params.sourcePath} to ${params.targetPath} (local to local)`,
            },
          ],
        };
      } else if (params.sourceConnectionId === 'local') {
        // Local to remote
        const targetSSH = connectionPool.get(params.targetConnectionId);
        if (!targetSSH) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Target connection ID '${params.targetConnectionId}' not found`
          );
        }

        if (params.createDirectories) {
          const targetDir = path.dirname(params.targetPath);
          await targetSSH.execCommand(`mkdir -p ${shellQuote(targetDir)}`);
        }

        await targetSSH.putFile(params.sourcePath, params.targetPath);
        return {
          content: [
            {
              type: 'text',
              text: `Successfully copied ${params.sourcePath} to ${params.targetConnectionId}:${params.targetPath}`,
            },
          ],
        };
      } else if (params.targetConnectionId === 'local') {
        // Remote to local
        const sourceSSH = connectionPool.get(params.sourceConnectionId);
        if (!sourceSSH) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Source connection ID '${params.sourceConnectionId}' not found`
          );
        }

        if (params.createDirectories) {
          const targetDir = path.dirname(params.targetPath);
          await fs.mkdir(targetDir, { recursive: true });
        }

        await sourceSSH.getFile(params.targetPath, params.sourcePath);
        return {
          content: [
            {
              type: 'text',
              text: `Successfully copied ${params.sourceConnectionId}:${params.sourcePath} to ${params.targetPath}`,
            },
          ],
        };
      } else {
        // Remote to remote
        const sourceSSH = connectionPool.get(params.sourceConnectionId);
        const targetSSH = connectionPool.get(params.targetConnectionId);
        
        if (!sourceSSH) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Source connection ID '${params.sourceConnectionId}' not found`
          );
        }
        if (!targetSSH) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Target connection ID '${params.targetConnectionId}' not found`
          );
        }

        // Use a temporary local file for remote-to-remote transfer
        const tempFile = `/tmp/mcp-ssh-temp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        try {
          await sourceSSH.getFile(tempFile, params.sourcePath);
          
          if (params.createDirectories) {
            const targetDir = path.dirname(params.targetPath);
            await targetSSH.execCommand(`mkdir -p ${shellQuote(targetDir)}`);
          }
          
          await targetSSH.putFile(tempFile, params.targetPath);
          await fs.unlink(tempFile); // Clean up temp file
          
          return {
            content: [
              {
                type: 'text',
                text: `Successfully copied ${params.sourceConnectionId}:${params.sourcePath} to ${params.targetConnectionId}:${params.targetPath}`,
              },
            ],
          };
        } catch (error) {
          // Clean up temp file on error
          try {
            await fs.unlink(tempFile);
          } catch {}
          throw error;
        }
      }
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `File copy failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleSSHListFiles(args: unknown) {
    const params = ListFilesSchema.parse(args);
    
    try {
      if (params.connectionId === 'local') {
        // List local files
        const files = await fs.readdir(params.remotePath, { withFileTypes: true });
        const fileList = files
          .filter((file) => params.showHidden || !file.name.startsWith('.'))
          .map((file) => ({
            name: file.name,
            type: file.isDirectory() ? 'directory' : 'file',
            path: path.join(params.remotePath, file.name)
          }));

        return {
          content: [
            {
              type: 'text',
              text: `Files in ${params.remotePath}:\n${JSON.stringify(fileList, null, 2)}`,
            },
          ],
        };
      } else {
        // List remote files
        const ssh = connectionPool.get(params.connectionId);
        if (!ssh) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Connection ID '${params.connectionId}' not found`
          );
        }

        const lsCommand = params.showHidden ? 'ls -la' : 'ls -l';
        const result = await ssh.execCommand(`${lsCommand} ${shellQuote(params.remotePath)}`);
        
        if (result.code !== 0) {
          throw new Error(`ls command failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: 'text',
              text: `Files in ${params.connectionId}:${params.remotePath}:\n${result.stdout}`,
            },
          ],
        };
      }
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `List files failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleSSHFileInfo(args: unknown) {
    const params = FileInfoSchema.parse(args);
    
    try {
      if (params.connectionId === 'local') {
        // Get local file info
        const stats = await fs.stat(params.filePath);
        const fileInfo = {
          path: params.filePath,
          size: stats.size,
          isDirectory: stats.isDirectory(),
          isFile: stats.isFile(),
          modified: stats.mtime.toISOString(),
          created: stats.birthtime.toISOString(),
          permissions: '0' + (stats.mode & parseInt('777', 8)).toString(8)
        };

        return {
          content: [
            {
              type: 'text',
              text: `File info for ${params.filePath}:\n${JSON.stringify(fileInfo, null, 2)}`,
            },
          ],
        };
      } else {
        // Get remote file info
        const ssh = connectionPool.get(params.connectionId);
        if (!ssh) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Connection ID '${params.connectionId}' not found`
          );
        }

        const result = await ssh.execCommand(`stat ${shellQuote(params.filePath)}`);
        
        if (result.code !== 0) {
          throw new Error(`stat command failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: 'text',
              text: `File info for ${params.connectionId}:${params.filePath}:\n${result.stdout}`,
            },
          ],
        };
      }
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Get file info failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleStartInteractiveShell(args: unknown) {
    const params = StartInteractiveShellSchema.parse(args);
    
    const ssh = connectionPool.get(params.connectionId);
    if (!ssh) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    if (shellSessions.has(params.sessionId)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Session ID '${params.sessionId}' already exists`
      );
    }

    try {
      // Create a shell session through SSH
      const shell = await ssh.requestShell({
        cols: params.cols,
        rows: params.rows,
        term: 'xterm-256color'
      });

      const emitter = new EventEmitter();
      const session: ShellSession = {
        shell: shell, // SSH ClientChannel
        ssh,
        emitter,
        buffer: '',
        isActive: true
      };

      // Set up data handling
      shell.on('data', (data: Buffer) => {
        const text = data.toString();
        session.buffer += text;
        emitter.emit('data', text);
      });

      shell.on('close', () => {
        session.isActive = false;
        emitter.emit('close');
      });

      shellSessions.set(params.sessionId, session);

      return {
        content: [
          {
            type: 'text',
            text: `Interactive shell session '${params.sessionId}' started successfully\nShell: ${params.shell}\nTerminal: ${params.cols}x${params.rows}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to start interactive shell: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleSendInput(args: unknown) {
    const params = SendInputSchema.parse(args);
    
    const session = shellSessions.get(params.sessionId);
    if (!session) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Session ID '${params.sessionId}' not found`
      );
    }

    if (!session.isActive) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Session '${params.sessionId}' is not active`
      );
    }

    try {
      if (params.simulateTyping) {
        // Simulate human typing with random delays
        for (const char of params.input) {
          session.shell.write(char);
          // Random delay between 50-150ms per character
          await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));
        }
      } else {
        session.shell.write(params.input);
      }

      return {
        content: [
          {
            type: 'text',
            text: `Input sent to session '${params.sessionId}'${params.simulateTyping ? ' (with typing simulation)' : ''}\nInput: ${params.input}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to send input: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleReadOutput(args: unknown) {
    const params = ReadOutputSchema.parse(args);
    
    const session = shellSessions.get(params.sessionId);
    if (!session) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Session ID '${params.sessionId}' not found`
      );
    }

    try {
      // Wait for output with timeout
      const output = await new Promise<string>((resolve, reject) => {
        const timeout = setTimeout(() => {
          resolve(session.buffer);
        }, params.timeout);

        if (session.buffer) {
          clearTimeout(timeout);
          resolve(session.buffer);
        } else {
          session.emitter.once('data', () => {
            clearTimeout(timeout);
            resolve(session.buffer);
          });
        }
      });

      const result = output;
      
      if (params.clearBuffer) {
        session.buffer = '';
      }

      return {
        content: [
          {
            type: 'text',
            text: `Output from session '${params.sessionId}':\n${result}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to read output: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleCloseInteractiveShell(args: unknown) {
    const params = CloseInteractiveShellSchema.parse(args);
    
    const session = shellSessions.get(params.sessionId);
    if (!session) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Session ID '${params.sessionId}' not found`
      );
    }

    try {
      session.shell.close();
      session.isActive = false;
      shellSessions.delete(params.sessionId);

      return {
        content: [
          {
            type: 'text',
            text: `Interactive shell session '${params.sessionId}' closed successfully`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to close session: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleSaveCredential(args: unknown) {
    const params = SaveCredentialSchema.parse(args);
    
    if (credentialStore.has(params.credentialId)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Credential ID '${params.credentialId}' already exists`
      );
    }

    if (!params.password && !params.privateKeyPath) {
      throw new McpError(
        ErrorCode.InvalidParams,
        'Either password or privateKeyPath must be provided'
      );
    }

    const credential: StoredCredential = {
      host: params.host,
      port: params.port || 22,
      username: params.username,
      password: params.password,
      privateKeyPath: params.privateKeyPath,
      passphrase: params.passphrase,
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString()
    };

    credentialStore.set(params.credentialId, credential);

    return {
      content: [
        {
          type: 'text',
          text: `Credential '${params.credentialId}' saved successfully for ${params.username}@${params.host}:${params.port || 22}`,
        },
      ],
    };
  }

  private async handleListCredentials(args: unknown) {
    ListCredentialsSchema.parse(args);
    
    const credentials = Array.from(credentialStore.entries()).map(([id, cred]) => ({
      credentialId: id,
      host: cred.host,
      port: cred.port,
      username: cred.username,
      hasPassword: !!cred.password,
      hasPrivateKey: !!cred.privateKeyPath,
      createdAt: cred.createdAt,
      lastUsed: cred.lastUsed
    }));

    return {
      content: [
        {
          type: 'text',
          text: credentials.length > 0 
            ? `Saved credentials:\n${credentials.map(c => 
                `- ${c.credentialId}: ${c.username}@${c.host}:${c.port} (${c.hasPassword ? 'password' : 'key'}) - Last used: ${c.lastUsed}`
              ).join('\n')}`
            : 'No saved credentials found',
        },
      ],
    };
  }

  private async handleDeleteCredential(args: unknown) {
    const params = DeleteCredentialSchema.parse(args);
    
    if (!credentialStore.has(params.credentialId)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Credential ID '${params.credentialId}' not found`
      );
    }

    const credential = credentialStore.get(params.credentialId)!;
    credentialStore.delete(params.credentialId);

    return {
      content: [
        {
          type: 'text',
          text: `Credential '${params.credentialId}' (${credential.username}@${credential.host}) deleted successfully`,
        },
      ],
    };
  }

  private async handleConnectWithCredential(args: unknown) {
    const params = ConnectWithCredentialSchema.parse(args);
    
    if (connectionPool.has(params.connectionId)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' already exists`
      );
    }

    const credential = credentialStore.get(params.credentialId);
    if (!credential) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Credential ID '${params.credentialId}' not found`
      );
    }

    const ssh = new NodeSSH();
    
    // Host key verification against known_hosts (fail closed; see src/host-key-verify.ts)
    const hostKeyCheck = createHostVerifier(credential.host, credential.port);

    try {
      const connectConfig: any = {
        host: credential.host,
        port: credential.port,
        username: credential.username,
        hostVerifier: hostKeyCheck.hostVerifier,
      };

      if (credential.privateKeyPath) {
        const privateKey = await fs.readFile(credential.privateKeyPath, 'utf8');
        connectConfig.privateKey = privateKey;
        if (credential.passphrase) {
          connectConfig.passphrase = credential.passphrase;
        }
      } else if (credential.password) {
        connectConfig.password = credential.password;
      } else {
        throw new McpError(
          ErrorCode.InvalidParams,
          'Credential has neither password nor private key'
        );
      }

      await ssh.connect(connectConfig);
      connectionPool.set(params.connectionId, ssh);

      // Initialize connection context
      connectionContexts.set(params.connectionId, {
        ssh,
        currentWorkingDirectory: undefined,
        defaultWorkingDirectory: undefined
      });

      // Update last used timestamp
      credential.lastUsed = new Date().toISOString();
      credentialStore.set(params.credentialId, credential);

      return {
        content: [
          {
            type: 'text',
            text: `Successfully connected to ${credential.host}:${credential.port} as ${credential.username} using saved credential '${params.credentialId}' (Connection ID: ${params.connectionId})`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `SSH connection failed: ${hostKeyCheck.lastFailure() ?? (error instanceof Error ? error.message : String(error))}`
      );
    }
  }

  private async handleSetWorkingDirectory(args: unknown) {
    const params = SetWorkingDirectorySchema.parse(args);
    
    const context = connectionContexts.get(params.connectionId);
    if (!context) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    try {
      // Verify the directory exists
      const result = await context.ssh.execCommand(`test -d ${shellQuote(params.workingDirectory)} && echo "exists"`);
      if (result.code !== 0) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Directory '${params.workingDirectory}' does not exist or is not accessible`
        );
      }

      // Set the working directory
      context.currentWorkingDirectory = params.workingDirectory;
      
      return {
        content: [
          {
            type: 'text',
            text: `Working directory set to: ${params.workingDirectory}`,
          },
        ],
      };
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to set working directory: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleGetWorkingDirectory(args: unknown) {
    const params = GetWorkingDirectorySchema.parse(args);
    
    const context = connectionContexts.get(params.connectionId);
    if (!context) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    try {
      let currentDir = context.currentWorkingDirectory;
      
      if (!currentDir) {
        // Get current directory from remote system
        const result = await context.ssh.execCommand('pwd');
        if (result.code === 0) {
          currentDir = result.stdout.trim();
          context.currentWorkingDirectory = currentDir;
        } else {
          throw new McpError(
            ErrorCode.InternalError,
            `Failed to get current directory: ${result.stderr}`
          );
        }
      }
      
      return {
        content: [
          {
            type: 'text',
            text: `Current working directory: ${currentDir}`,
          },
        ],
      };
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get working directory: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleDockerDeploy(args: unknown) {
    const params = DockerDeploySchema.parse(args);
    
    const context = connectionContexts.get(params.connectionId);
    if (!context) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    try {
      // Set working directory for this operation
      const workingDir = params.workingDirectory;
      
      let command = '';
      let envPrefix = '';
      
      // Build environment variables prefix
      if (params.envVars) {
        const envVarStrings = Object.entries(params.envVars).map(([key, value]) => {
          if (!isValidEnvVarName(key)) {
            throw new McpError(
              ErrorCode.InvalidParams,
              `Invalid environment variable name: '${key}'`
            );
          }
          return `${key}=${shellQuote(value)}`;
        });
        envPrefix = envVarStrings.join(' ') + ' ';
      }
      
      switch (params.deploymentType) {
        case 'compose':
          command = `${envPrefix}docker-compose`;
          if (params.composeFile && params.composeFile !== 'docker-compose.yml') {
            command += ` -f ${shellQuote(params.composeFile)}`;
          }
          command += ' up';
          if (params.detached) {
            command += ' -d';
          }
          break;
          
        case 'build':
          if (!params.imageName) {
            throw new McpError(
              ErrorCode.InvalidParams,
              'imageName is required for build deployment type'
            );
          }
          command = `${envPrefix}docker build`;
          if (params.buildArgs) {
            Object.entries(params.buildArgs).forEach(([key, value]) => {
              if (!isValidEnvVarName(key)) {
                throw new McpError(
                  ErrorCode.InvalidParams,
                  `Invalid build argument name: '${key}'`
                );
              }
              command += ` --build-arg ${key}=${shellQuote(value)}`;
            });
          }
          command += ` -t ${shellQuote(params.imageName)} .`;
          break;
          
        case 'run':
          if (!params.imageName) {
            throw new McpError(
              ErrorCode.InvalidParams,
              'imageName is required for run deployment type'
            );
          }
          command = `${envPrefix}docker run`;
          if (params.detached) {
            command += ' -d';
          }
          if (params.containerName) {
            command += ` --name ${shellQuote(params.containerName)}`;
          }
          if (params.ports) {
            params.ports.forEach(port => {
              command += ` -p ${shellQuote(port)}`;
            });
          }
          if (params.volumes) {
            params.volumes.forEach(volume => {
              command += ` -v ${shellQuote(volume)}`;
            });
          }
          command += ` ${shellQuote(params.imageName)}`;
          break;
      }
      
      const result = await context.ssh.execCommand(command, {
        cwd: workingDir,
      });
      
      return {
        content: [
          {
            type: 'text',
            text: `Docker ${params.deploymentType} deployment:\nCommand: ${command}\nExit Code: ${result.code}\n\nSTDOUT:\n${result.stdout}\n\nSTDERR:\n${result.stderr}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Docker deployment failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async handleDockerStatus(args: unknown) {
    const params = DockerStatusSchema.parse(args);
    
    const context = connectionContexts.get(params.connectionId);
    if (!context) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Connection ID '${params.connectionId}' not found`
      );
    }

    try {
      const workingDir = params.workingDirectory || context.currentWorkingDirectory;
      
      // Get Docker container status
      const psResult = await context.ssh.execCommand('docker ps -a', {
        cwd: workingDir,
      });
      
      // Get Docker Compose status if compose file exists
      let composeStatus = '';
      if (workingDir) {
        const composeResult = await context.ssh.execCommand('docker-compose ps', {
          cwd: workingDir,
        });
        if (composeResult.code === 0) {
          composeStatus = `\n\nDocker Compose Status:\n${composeResult.stdout}`;
        }
      }
      
      return {
        content: [
          {
            type: 'text',
            text: `Docker Status (${workingDir || 'current directory'}):\n\nContainer Status:\n${psResult.stdout}${composeStatus}`,
          },
        ],
      };
    } catch (error) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get Docker status: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('SSH MCP server running on stdio');
  }
}

const server = new SSHMCPServer();
server.run().catch(console.error);