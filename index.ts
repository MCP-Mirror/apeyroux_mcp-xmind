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
    relationships?: XMindRelationship[];
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

interface XMindRelationship {
    id: string;
    end1Id: string;
    end2Id: string;
    title?: string;
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
            const allNodes = content.map((sheet: { 
                rootTopic: XMindTopic; 
                title?: string;
                relationships?: XMindRelationship[];
            }) => {
                const rootNode = this.processNode(sheet.rootTopic, sheet.title || "Untitled Map");
                // Ajouter les relations au nœud racine
                if (sheet.relationships) {
                    rootNode.relationships = sheet.relationships;
                }
                return rootNode;
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

// Schema definitions
const ReadXMindArgsSchema = z.object({
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
    searchIn: z.array(z.enum(['title', 'notes', 'labels', 'callouts', 'tasks'])).optional(),
    caseSensitive: z.boolean().optional(),
    taskStatus: z.enum(['todo', 'done']).optional(), // Ajout du filtre de statut de tâche
});

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
async function searchInXMindContent(filePath: string, searchText: string): Promise<boolean> {
    try {
        const zip = new AdmZip(filePath);
        const contentEntry = zip.getEntry("content.json");
        if (!contentEntry) return false;

        const content = zip.readAsText(contentEntry);
        return content.toLowerCase().includes(searchText.toLowerCase());
    } catch (error) {
        console.error(`Error reading XMind file ${filePath}:`, error);
        return false;
    }
}

// Modification de la fonction searchXMindFiles
async function searchXMindFiles(pattern: string): Promise<string[]> {
    const matches: string[] = [];
    const contentMatches: string[] = [];
    const searchPattern = pattern.toLowerCase();

    async function searchInDirectory(currentDir: string) {
        try {
            const entries = await fs.readdir(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(currentDir, entry.name);

                if (entry.isDirectory()) {
                    const normalizedPath = path.normalize(fullPath).toLowerCase();
                    if (allowedDirectories.some(allowed => normalizedPath.startsWith(allowed))) {
                        await searchInDirectory(fullPath);
                    }
                } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.xmind')) {
                    const searchableText = [
                        entry.name.toLowerCase(),
                        path.basename(entry.name, '.xmind').toLowerCase(),
                        fullPath.toLowerCase()
                    ];

                    if (searchPattern === '' || 
                        searchableText.some(text => text.includes(searchPattern))) {
                        matches.push(fullPath);
                    } else {
                        // Si le pattern n'est pas trouvé dans le nom, chercher dans le contenu
                        if (await searchInXMindContent(fullPath, searchPattern)) {
                            contentMatches.push(fullPath);
                        }
                    }
                }
            }
        } catch (error) {
            console.error(`Warning: Error searching directory ${currentDir}:`, error);
        }
    }

    await Promise.all(allowedDirectories.map(dir => searchInDirectory(dir)));

    // Combiner et trier les résultats
    const allMatches = [
        ...matches.sort((a, b) => path.basename(a).localeCompare(path.basename(b))),
        ...contentMatches.sort((a, b) => path.basename(a).localeCompare(path.basename(b)))
    ];

    return allMatches;
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
    taskStatus?: 'todo' | 'done';
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
        caseSensitive?: boolean,
        taskStatus?: 'todo' | 'done'
    } = {},
    parents: string[] = []
): NodeMatch[] {
    const matches: NodeMatch[] = [];
    const searchQuery = options.caseSensitive ? query : query.toLowerCase();
    const searchFields = options.searchIn || ['title', 'notes', 'labels', 'callouts', 'tasks'];

    const matchedIn: string[] = [];

    // Fonction helper pour la recherche de texte sécurisée
    const matchesText = (text: string | undefined): boolean => {
        if (!text) return false;
        const searchIn = options.caseSensitive ? text : text.toLowerCase();
        return searchIn.includes(searchQuery);
    };

    // Vérification du statut de tâche si spécifié
    if (options.taskStatus && node.taskStatus) {
        if (node.taskStatus !== options.taskStatus) {
            // Si le statut ne correspond pas, ignorer ce nœud
            return [];
        }
    }

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
    if (searchFields.includes('tasks') && node.taskStatus) {
        matchedIn.push('tasks');
    }

    // Si on a trouvé des correspondances ou si c'est une tâche correspondante, ajouter ce nœud
    const shouldIncludeNode = matchedIn.length > 0 || 
        (options.taskStatus && node.taskStatus === options.taskStatus);

    if (shouldIncludeNode && node.id) {
        matches.push({
            id: node.id,
            title: node.title,
            path: getNodePath(node, parents),
            sheet: node.sheetTitle || 'Untitled Map',
            matchedIn,
            notes: node.notes?.content,
            labels: node.labels,
            callouts: node.callouts,
            taskStatus: node.taskStatus // Ajout du statut de tâche dans les résultats
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
                - Include all relationships between nodes with their IDs and titles
                - Extract callouts attached to topics
                - Generate text or markdown summaries
                - Search for specific content
                - Get hierarchical path to any node
                - Filter content by labels, task status, or node depth
                - Extract all URLs and external references
                - Analyze relationships and connections between topics
                Input: File path to .xmind file
                Output: JSON structure containing nodes, relationships, and callouts`,
                inputSchema: zodToJsonSchema(ReadXMindArgsSchema),
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
                - Search through titles, notes, labels, callouts and tasks
                - Filter by task status (todo/done)
                - Find nodes by their relationships
                - Configure which fields to search in
                - Case-sensitive or insensitive search
                - Get full context including task status
                - Returns all matching nodes with their IDs
                - Includes relationship information and task status
                Input: {
                    path: Path to .xmind file,
                    query: Search text,
                    searchIn: Array of fields to search in ['title', 'notes', 'labels', 'callouts', 'tasks'],
                    taskStatus: 'todo' | 'done' (optional),
                    caseSensitive: Boolean (optional)
                }
                Output: Detailed search results with task status and context`,
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
                        caseSensitive: parsed.data.caseSensitive,
                        taskStatus: parsed.data.taskStatus
                    })
                );

                const result: SearchResult = {
                    query: parsed.data.query,
                    matches,
                    totalMatches: matches.length,
                    searchedIn: parsed.data.searchIn || ['title', 'notes', 'labels', 'callouts', 'tasks']
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