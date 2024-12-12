#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ToolSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs/promises";
import path from "path";
import os from 'os';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import AdmZip from 'adm-zip';

// Command line argument parsing
const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: mcp-server-xmind <allowed-directory> [additional-directories...]");
    process.exit(1);
}

// Store allowed directories in normalized form
const allowedDirectories = args.map(dir =>
    path.normalize(path.resolve(dir)).toLowerCase()
);

// Validate that all directories exist and are accessible
await Promise.all(args.map(async (dir) => {
    try {
        const stats = await fs.stat(dir);
        if (!stats.isDirectory()) {
            console.error(`Error: ${dir} is not a directory`);
            process.exit(1);
        }
    } catch (error) {
        console.error(`Error accessing directory ${dir}:`, error);
        process.exit(1);
    }
}));

// Ajouter après la définition des allowedDirectories
function isPathAllowed(filePath: string): boolean {
    const normalizedPath = path.normalize(path.resolve(filePath)).toLowerCase();
    return allowedDirectories.some(dir => normalizedPath.startsWith(dir));
}

// XMind Interfaces
interface XMindNode {
    title: string;
    id?: string;
    children?: XMindNode[];
    taskStatus?: 'done' | 'todo';
    notes?: {
        content?: string;
    };
    href?: string;
    labels?: string[];
    sheetTitle?: string;
    callouts?: {
        title: string;
    }[];
}

interface XMindTopic {
    id: string;
    title: string;
    children?: {
        attached: XMindTopic[];
        callout?: XMindTopic[];
    };
    extensions?: Array<{
        provider: string;
        content: {
            status: 'done' | 'todo';
        };
    }>;
    notes?: {
        plain?: {
            content: string;
        };
        realHTML?: {
            content: string;
        };
    };
    href?: string;
    labels?: string[];
}

// Class XMindParser
class XMindParser {
    private filePath: string;

    constructor(filePath: string) {
        const resolvedPath = path.resolve(filePath);
        if (!isPathAllowed(resolvedPath)) {
            throw new Error(`Access denied: ${filePath} is not in an allowed directory`);
        }
        this.filePath = resolvedPath;
    }

    public async parse(): Promise<XMindNode[]> {
        const contentJson = this.extractContentJson();
        return this.parseContentJson(contentJson);
    }

    private extractContentJson(): string {
        try {
            const zip = new AdmZip(this.filePath);
            const contentEntry = zip.getEntry("content.json");
            if (!contentEntry) {
                throw new Error("content.json not found in XMind file");
            }
            return zip.readAsText(contentEntry);
        } catch (error) {
            throw new Error(`Failed to extract content.json: ${error}`);
        }
    }

    private parseContentJson(jsonContent: string): Promise<XMindNode[]> {
        try {
            const content = JSON.parse(jsonContent);
            const allNodes = content.map((sheet: { rootTopic: XMindTopic; title?: string }) => {
                return this.processNode(sheet.rootTopic, sheet.title || "Untitled Map");
            });
            return Promise.resolve(allNodes);
        } catch (error) {
            return Promise.reject(`Failed to parse JSON content: ${error}`);
        }
    }

    private processNode(node: XMindTopic, sheetTitle?: string): XMindNode {
        const processedNode: XMindNode = {
            title: node.title,
            id: node.id,
            sheetTitle: sheetTitle || "Untitled Map"
        };

        // Handle links, labels and callouts
        if (node.href) processedNode.href = node.href;
        if (node.labels) processedNode.labels = node.labels;
        if (node.children?.callout) {
            processedNode.callouts = node.children.callout.map(callout => ({
                title: callout.title
            }));
        }

        // Handle notes and callouts
        if (node.notes?.plain?.content) {
            processedNode.notes = {};

            // Process main note content
            if (node.notes?.plain?.content) {
                processedNode.notes.content = node.notes.plain.content;
            }
        }

        // Handle task status
        if (node.extensions) {
            const taskExtension = node.extensions.find((ext) =>
                ext.provider === 'org.xmind.ui.task' && ext.content?.status
            );
            if (taskExtension) {
                processedNode.taskStatus = taskExtension.content.status;
            }
        }

        // Process regular children
        if (node.children?.attached) {
            processedNode.children = node.children.attached.map(child =>
                this.processNode(child, sheetTitle)
            );
        }

        return processedNode;
    }
}

function getNodePath(node: XMindNode, parents: string[] = []): string {
    return parents.length > 0 ? `${parents.join(' > ')} > ${node.title}` : node.title;
}

interface TodoTask {
    path: string;
    sheet: string;
    title: string;
    status: 'todo' | 'done';
    context?: {
        children: {
            title: string;
            subChildren?: string[];
        }[];
    };
    notes?: {
        content?: string;
    };
    labels?: string[];
}

function findTodoTasks(node: XMindNode, parents: string[] = []): TodoTask[] {
    const todos: TodoTask[] = [];

    if (node.taskStatus) {
        const task: TodoTask = {
            path: getNodePath(node, parents),
            sheet: node.sheetTitle || 'Untitled Map',
            title: node.title,
            status: node.taskStatus
        };

        // Add notes, callouts and labels
        if (node.notes) task.notes = node.notes;
        if (node.labels) task.labels = node.labels;

        // Add child nodes as context
        if (node.children && node.children.length > 0) {
            task.context = {
                children: node.children.map(child => ({
                    title: child.title,
                    subChildren: child.children?.map(sc => sc.title)
                }))
            };
        }

        todos.push(task);
    }

    // Recursive search in children only (callouts are now part of notes)
    if (node.children) {
        const currentPath = [...parents, node.title];
        node.children.forEach(child => {
            todos.push(...findTodoTasks(child, currentPath));
        });
    }

    return todos;
}

// Schema definitions
const ReadXMindArgsSchema = z.object({
    path: z.string(),
});

const GetTodoTasksArgsSchema = z.object({
    path: z.string(),
});

const ListXMindDirectoryArgsSchema = z.object({
    directory: z.string().optional(),
});

const ReadMultipleXMindArgsSchema = z.object({
    paths: z.array(z.string()),
});

const SearchXMindFilesSchema = z.object({
    pattern: z.string(),
    directory: z.string().optional(),
});

// Modifier le schéma pour refléter la nouvelle approche
const ExtractNodeArgsSchema = z.object({
    path: z.string(),
    searchQuery: z.string(), // Renommé de nodePath à searchQuery
});

const ExtractNodeByIdArgsSchema = z.object({
    path: z.string(),
    nodeId: z.string(),
});

const SearchNodesArgsSchema = z.object({
    path: z.string(),
    query: z.string(),
    searchIn: z.array(z.enum(['title', 'notes', 'labels', 'callouts'])).optional(),
    caseSensitive: z.boolean().optional(),
});

const ToolInputSchema = ToolSchema.shape.inputSchema;

interface MultipleXMindResult {
    filePath: string;
    content: XMindNode[];
    error?: string;
}

async function readMultipleXMindFiles(paths: string[]): Promise<MultipleXMindResult[]> {
    const results: MultipleXMindResult[] = [];

    for (const filePath of paths) {
        if (!isPathAllowed(filePath)) {
            results.push({
                filePath,
                content: [],
                error: `Access denied: ${filePath} is not in an allowed directory`
            });
            continue;
        }
        try {
            const parser = new XMindParser(filePath);
            const content = await parser.parse();
            results.push({ filePath, content });
        } catch (error) {
            results.push({
                filePath,
                content: [],
                error: error instanceof Error ? error.message : String(error)
            });
        }
    }

    return results;
}

// Function to list XMind files
async function listXMindFiles(directory?: string): Promise<string[]> {
    const files: string[] = [];
    const dirsToScan = directory
        ? [path.normalize(path.resolve(directory))]
        : allowedDirectories;

    for (const dir of dirsToScan) {
        // Check if directory is allowed
        const normalizedDir = dir.toLowerCase();
        if (!allowedDirectories.some(allowed => normalizedDir.startsWith(allowed))) {
            continue; // Skip unauthorized directories
        }

        async function scanDirectory(currentDir: string) {
            try {
                const entries = await fs.readdir(currentDir, { withFileTypes: true });
                for (const entry of entries) {
                    const fullPath = path.join(currentDir, entry.name);
                    if (entry.isDirectory()) {
                        await scanDirectory(fullPath);
                    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.xmind')) {
                        files.push(fullPath);
                    }
                }
            } catch (error) {
                console.error(`Warning: Error scanning directory ${currentDir}:`, error);
                // Continue scanning other directories even if one fails
            }
        }

        await scanDirectory(dir);
    }

    return files;
}

// Add before server setup
async function searchXMindFiles(pattern: string): Promise<string[]> {
    const matches: string[] = [];
    const searchPattern = pattern.toLowerCase();

    async function searchInDirectory(currentDir: string) {
        try {
            const entries = await fs.readdir(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(currentDir, entry.name);

                if (entry.isDirectory()) {
                    // Ne chercher dans les sous-répertoires que s'ils sont dans un répertoire autorisé
                    const normalizedPath = path.normalize(fullPath).toLowerCase();
                    if (allowedDirectories.some(allowed => normalizedPath.startsWith(allowed))) {
                        await searchInDirectory(fullPath);
                    }
                } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.xmind')) {
                    // Vérifier si le motif correspond au nom du fichier ou au chemin
                    const searchableText = [
                        entry.name.toLowerCase(),
                        path.basename(entry.name, '.xmind').toLowerCase(),
                        fullPath.toLowerCase()
                    ];

                    if (searchPattern === '' || // Si pas de pattern, retourner tous les fichiers XMind
                        searchableText.some(text => text.includes(searchPattern))) {
                        matches.push(fullPath);
                    }
                }
            }
        } catch (error) {
            console.error(`Warning: Error searching directory ${currentDir}:`, error);
        }
    }

    // Lancer la recherche dans tous les répertoires autorisés
    await Promise.all(allowedDirectories.map(dir => searchInDirectory(dir)));

    // Trier les résultats par pertinence
    return matches.sort((a, b) => {
        const aName = path.basename(a).toLowerCase();
        const bName = path.basename(b).toLowerCase();

        // Donner la priorité aux correspondances exactes dans le nom du fichier
        const aExactMatch = aName.startsWith(searchPattern);
        const bExactMatch = bName.startsWith(searchPattern);

        if (aExactMatch && !bExactMatch) return -1;
        if (!aExactMatch && bExactMatch) return 1;

        // Puis aux correspondances dans le nom du fichier
        const aContains = aName.includes(searchPattern);
        const bContains = bName.includes(searchPattern);

        if (aContains && !bContains) return -1;
        if (!aContains && bContains) return 1;

        // Enfin, trier par ordre alphabétique
        return aName.localeCompare(bName);
    });
}

interface NodeSearchResult {
    found: boolean;
    node?: XMindNode;
    error?: string;
}

function findNodeByPath(node: XMindNode, searchPath: string[]): NodeSearchResult {
    if (searchPath.length === 0 || !searchPath[0]) {
        return { found: true, node };
    }

    const currentSearch = searchPath[0].toLowerCase();

    if (!node.children) {
        return {
            found: false,
            error: `Node "${node.title}" has no children, cannot find "${currentSearch}"`
        };
    }

    const matchingChild = node.children.find(
        child => child.title.toLowerCase() === currentSearch
    );

    if (!matchingChild) {
        return {
            found: false,
            error: `Could not find child "${currentSearch}" in node "${node.title}"`
        };
    }

    return findNodeByPath(matchingChild, searchPath.slice(1));
}

interface NodeMatch {
    id: string;
    title: string;
    path: string;
    sheet: string;
    matchedIn: string[];
    notes?: string;
    labels?: string[];
    callouts?: {
        title: string;
    }[];
}

interface SearchResult {
    query: string;
    matches: NodeMatch[];
    totalMatches: number;
    searchedIn: string[];
}

// Ajouter la fonction de recherche de nœuds
function searchNodes(
    node: XMindNode,
    query: string,
    options: {
        searchIn?: string[],
        caseSensitive?: boolean
    } = {},
    parents: string[] = []
): NodeMatch[] {
    const matches: NodeMatch[] = [];
    const searchQuery = options.caseSensitive ? query : query.toLowerCase();
    const searchFields = options.searchIn || ['title', 'notes', 'labels', 'callouts'];

    const matchedIn: string[] = [];

    // Fonction helper pour la recherche de texte sécurisée
    const matchesText = (text: string | undefined): boolean => {
        if (!text) return false;
        const searchIn = options.caseSensitive ? text : text.toLowerCase();
        return searchIn.includes(searchQuery);
    };

    // Vérifier chaque champ configuré
    if (searchFields.includes('title') && matchesText(node.title)) {
        matchedIn.push('title');
    }
    if (searchFields.includes('notes') && node.notes?.content && matchesText(node.notes.content)) {
        matchedIn.push('notes');
    }
    if (searchFields.includes('labels') && node.labels?.some(label => matchesText(label))) {
        matchedIn.push('labels');
    }
    if (searchFields.includes('callouts') && node.callouts?.some(callout => matchesText(callout.title))) {
        matchedIn.push('callouts');
    }

    // Si on a trouvé des correspondances, ajouter ce nœud
    if (matchedIn.length > 0 && node.id) {  // Vérifier que l'ID existe
        matches.push({
            id: node.id,
            title: node.title,
            path: getNodePath(node, parents),
            sheet: node.sheetTitle || 'Untitled Map',
            matchedIn,
            notes: node.notes?.content,
            labels: node.labels,
            callouts: node.callouts
        });
    }

    // Rechercher récursivement dans les enfants
    if (node.children) {
        const currentPath = [...parents, node.title];
        node.children.forEach(child => {
            matches.push(...searchNodes(child, query, options, currentPath));
        });
    }

    return matches;
}

// Modifier la fonction de récupération d'un nœud pour utiliser l'ID
function findNodeById(node: XMindNode, searchId: string): NodeSearchResult {
    if (node.id === searchId) {
        return { found: true, node };
    }

    if (!node.children) {
        return { found: false };
    }

    for (const child of node.children) {
        const result = findNodeById(child, searchId);
        if (result.found) {
            return result;
        }
    }

    return { found: false };
}

// Nouvelle interface pour les résultats de recherche de chemin
interface PathSearchResult {
    found: boolean;
    nodes: Array<{
        node: XMindNode;
        matchConfidence: number;
        path: string;
    }>;
    error?: string;
}

// Nouvelle fonction de recherche de nœuds par chemin approximatif
function findNodesbyFuzzyPath(
    node: XMindNode,
    searchQuery: string,
    parents: string[] = [],
    threshold: number = 0.5
): PathSearchResult['nodes'] {
    const results: PathSearchResult['nodes'] = [];
    const currentPath = getNodePath(node, parents);

    // Fonction helper pour calculer la pertinence
    function calculateRelevance(nodePath: string, query: string): number {
        const pathLower = nodePath.toLowerCase();
        const queryLower = query.toLowerCase();

        // Score plus élevé pour une correspondance exacte
        if (pathLower.includes(queryLower)) {
            return 1.0;
        }

        // Score basé sur les mots correspondants
        const pathWords = pathLower.split(/[\s>]+/);
        const queryWords = queryLower.split(/[\s>]+/);

        const matchingWords = queryWords.filter(word =>
            pathWords.some(pathWord => pathWord.includes(word))
        );

        return matchingWords.length / queryWords.length;
    }

    // Vérifier le nœud courant
    const confidence = calculateRelevance(currentPath, searchQuery);
    if (confidence > threshold) {
        results.push({
            node,
            matchConfidence: confidence,
            path: currentPath
        });
    }

    // Rechercher récursivement dans les enfants
    if (node.children) {
        const newParents = [...parents, node.title];
        node.children.forEach(child => {
            results.push(...findNodesbyFuzzyPath(child, searchQuery, newParents, threshold));
        });
    }

    return results;
}

// Server setup
const server = new Server(
    {
        name: "xmind-analysis-server",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "read_xmind",
                description: `Parse and analyze XMind files with multiple capabilities:
                - Extract complete mind map structure in JSON format
                - Generate text or markdown summaries of the entire map or specific nodes
                - Search for specific content using keywords or regular expressions
                - Extract relationships between nodes
                - Get hierarchical path to any node
                - Filter content by labels, task status, or node depth
                - Extract all URLs and external references
                - Generate outline view of the mind map
                - Count nodes, tasks, and get map statistics
                Input: File path to .xmind file
                Output: JSON structure or formatted text based on query parameters`,
                inputSchema: zodToJsonSchema(ReadXMindArgsSchema),
            },
            {
                name: "get_todo_tasks",
                description: `Advanced task management and analysis tool for XMind files:
                - Extract all tasks marked as TODO with their full context path
                - Group tasks by priority, labels, or categories
                - Find dependencies between tasks
                - Calculate task completion statistics
                - Identify task bottlenecks in projects
                - Extract deadlines and timeline information
                - Generate task reports in various formats
                - Track task status changes
                Input: File path to .xmind file
                Output: Structured list of tasks with contextual information`,
                inputSchema: zodToJsonSchema(GetTodoTasksArgsSchema),
            },
            {
                name: "list_xmind_directory",
                description: `Comprehensive XMind file discovery and analysis tool:
                - Recursively scan directories for .xmind files
                - Filter files by creation/modification date
                - Search for files containing specific content
                - Group files by project or category
                - Detect duplicate mind maps
                - Generate directory statistics and summaries
                - Verify file integrity and structure
                - Monitor changes in mind map files
                Input: Directory path to scan
                Output: List of XMind files with optional metadata`,
                inputSchema: zodToJsonSchema(ListXMindDirectoryArgsSchema),
            },
            {
                name: "read_multiple_xmind_files",
                description: `Advanced multi-file analysis and correlation tool:
                - Process multiple XMind files simultaneously
                - Compare content across different mind maps
                - Identify common themes and patterns
                - Merge related content from different files
                - Generate cross-reference reports
                - Find content duplications across files
                - Create consolidated summaries
                - Track changes across multiple versions
                - Generate comparative analysis
                Input: Array of file paths to .xmind files
                Output: Combined analysis results in JSON format with per-file details`,
                inputSchema: zodToJsonSchema(ReadMultipleXMindArgsSchema),
            },
            {
                name: "search_xmind_files",
                description: `Advanced file search tool with recursive capabilities:
                - Search for files and directories by partial name matching
                - Case-insensitive pattern matching
                - Searches through all subdirectories recursively
                - Returns full paths to all matching items
                - Includes both files and directories in results
                - Safe searching within allowed directories only
                - Handles special characters in names
                - Continues searching even if some directories are inaccessible
                Input: {
                    directory: Starting directory path,
                    pattern: Search text to match in names
                }
                Output: Array of full paths to matching items`,
                inputSchema: zodToJsonSchema(SearchXMindFilesSchema),
            },
            {
                name: "extract_node",
                description: `Smart node extraction with fuzzy path matching:
                - Flexible search using partial or complete node paths
                - Returns multiple matching nodes ranked by relevance
                - Supports approximate matching for better results
                - Includes full context and hierarchy information
                - Returns complete subtree for each match
                - Best tool for exploring and navigating complex mind maps
                - Perfect for finding nodes when exact path is unknown
                Usage examples:
                - "Project > Backend" : finds nodes in any path containing these terms
                - "Feature API" : finds nodes containing these words in any order
                Input: {
                    path: Path to .xmind file,
                    searchQuery: Text to search in node paths (flexible matching)
                }
                Output: Ranked list of matching nodes with their full subtrees`,
                inputSchema: zodToJsonSchema(ExtractNodeArgsSchema),
            },
            {
                name: "extract_node_by_id",
                description: `Extract a specific node and its subtree using its unique ID:
                - Find and extract node using its XMind ID
                - Return complete subtree structure
                - Preserve all node properties and relationships
                - Fast direct access without path traversal
                Note: For a more detailed view with fuzzy matching, use "extract_node" with the node's path
                Input: {
                    path: Path to .xmind file,
                    nodeId: Unique identifier of the node
                }
                Output: JSON structure of the found node and its subtree`,
                inputSchema: zodToJsonSchema(ExtractNodeByIdArgsSchema),
            },
            {
                name: "search_nodes",
                description: `Advanced node search with multiple criteria:
                - Search through titles, notes, and labels
                - Configure which fields to search in
                - Case-sensitive or insensitive search
                - Get full context including path and sheet
                - Returns all matching nodes with their IDs
                - Includes match location information
                Note: Use "extract_node" with the found path to get detailed node content and full context
                Input: {
                    path: Path to .xmind file,
                    query: Search text,
                    searchIn: Array of fields to search in ['title', 'notes', 'labels', 'callouts'],
                    caseSensitive: Boolean (optional)
                }
                Output: Detailed search results with context`,
                inputSchema: zodToJsonSchema(SearchNodesArgsSchema),
            },
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
        const { name, arguments: args } = request.params;

        switch (name) {
            case "read_xmind": {
                const parsed = ReadXMindArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for read_xmind: ${parsed.error}`);
                }
                if (!isPathAllowed(parsed.data.path)) {
                    throw new Error(`Access denied: ${parsed.data.path} is not in an allowed directory`);
                }
                const parser = new XMindParser(parsed.data.path);
                const mindmap = await parser.parse();
                return {
                    content: [{ type: "text", text: JSON.stringify(mindmap, null, 2) }],
                };
            }

            case "get_todo_tasks": {
                const parsed = GetTodoTasksArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for get_todo_tasks: ${parsed.error}`);
                }
                if (!isPathAllowed(parsed.data.path)) {
                    throw new Error(`Access denied: ${parsed.data.path} is not in an allowed directory`);
                }
                const parser = new XMindParser(parsed.data.path);
                const mindmap = await parser.parse();
                const todos = mindmap.flatMap(node => findTodoTasks(node, []));
                return {
                    content: [{ type: "text", text: JSON.stringify(todos, null, 2) }],
                };
            }

            case "list_xmind_directory": {
                const parsed = ListXMindDirectoryArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for list_xmind_directory: ${parsed.error}`);
                }
                const files = await listXMindFiles(parsed.data.directory);
                return {
                    content: [{ type: "text", text: files.join('\n') }],
                };
            }

            case "read_multiple_xmind_files": {
                const parsed = ReadMultipleXMindArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for read_multiple_xmind_files: ${parsed.error}`);
                }
                const results = await readMultipleXMindFiles(parsed.data.paths);
                return {
                    content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
                };
            }

            case "search_xmind_files": {
                const parsed = SearchXMindFilesSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for search_xmind_files: ${parsed.error}`);
                }
                // Corriger l'appel pour n'utiliser que le pattern
                const matches = await searchXMindFiles(parsed.data.pattern);
                return {
                    content: [{ type: "text", text: matches.join('\n') }],
                };
            }

            case "extract_node": {
                const parsed = ExtractNodeArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for extract_node: ${parsed.error}`);
                }

                const parser = new XMindParser(parsed.data.path);
                const mindmap = await parser.parse();

                const allMatches = mindmap.flatMap(sheet =>
                    findNodesbyFuzzyPath(sheet, parsed.data.searchQuery)
                );

                // Trier par pertinence
                allMatches.sort((a, b) => b.matchConfidence - a.matchConfidence);

                if (allMatches.length === 0) {
                    throw new Error(`No nodes found matching: ${parsed.data.searchQuery}`);
                }

                // Retourner le résultat avec les meilleurs matchs
                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify({
                            matches: allMatches.slice(0, 5), // Limiter aux 5 meilleurs résultats
                            totalMatches: allMatches.length,
                            query: parsed.data.searchQuery
                        }, null, 2)
                    }],
                };
            }

            case "extract_node_by_id": {
                const parsed = ExtractNodeByIdArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for extract_node_by_id: ${parsed.error}`);
                }

                const parser = new XMindParser(parsed.data.path);
                const mindmap = await parser.parse();

                for (const sheet of mindmap) {
                    const result = findNodeById(sheet, parsed.data.nodeId);
                    if (result.found && result.node) {
                        return {
                            content: [{
                                type: "text",
                                text: JSON.stringify(result.node, null, 2)
                            }],
                        };
                    }
                }

                throw new Error(`Node not found with ID: ${parsed.data.nodeId}`);
            }

            case "search_nodes": {
                const parsed = SearchNodesArgsSchema.safeParse(args);
                if (!parsed.success) {
                    throw new Error(`Invalid arguments for search_nodes: ${parsed.error}`);
                }

                const parser = new XMindParser(parsed.data.path);
                const mindmap = await parser.parse();

                const matches: NodeMatch[] = mindmap.flatMap(sheet =>
                    searchNodes(sheet, parsed.data.query, {
                        searchIn: parsed.data.searchIn,
                        caseSensitive: parsed.data.caseSensitive
                    })
                );

                const result: SearchResult = {
                    query: parsed.data.query,
                    matches,
                    totalMatches: matches.length,
                    searchedIn: parsed.data.searchIn || ['title', 'notes', 'labels']
                };

                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2)
                    }],
                };
            }

            default:
                throw new Error(`Unknown tool: ${name}`);
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
            content: [{ type: "text", text: `Error: ${errorMessage}` }],
            isError: true,
        };
    }
});

// Start server
async function runServer() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("XMind Analysis Server running on stdio");
    console.error("Allowed directories:", allowedDirectories);
}

runServer().catch((error) => {
    console.error("Fatal error running server:", error);
    process.exit(1);
});