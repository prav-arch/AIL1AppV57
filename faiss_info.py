#!/usr/bin/env python
"""
Script to read FAISS database information and display statistics
"""
import os
import sys
import json
import logging
import faiss
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FAISS configuration
FAISS_INDEX_PATH = os.environ.get('FAISS_INDEX_PATH', 'data/faiss_index.bin')
FAISS_MAPPING_PATH = os.environ.get('FAISS_MAPPING_PATH', 'data/faiss_id_mapping.json')
FAISS_DIMENSION = int(os.environ.get('FAISS_DIMENSION', 384))

def get_index_size_bytes(index_path):
    """Get the size of the FAISS index file in bytes"""
    try:
        if os.path.exists(index_path):
            return os.path.getsize(index_path)
        return 0
    except Exception as e:
        logger.error(f"Error getting index size: {e}")
        return 0

def format_size(size_bytes):
    """Format byte size to human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

def load_id_mapping(mapping_path):
    """Load the ID mapping file"""
    try:
        if os.path.exists(mapping_path):
            with open(mapping_path, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        logger.error(f"Error loading ID mapping: {e}")
        return {}

def load_faiss_index(index_path):
    """Load the FAISS index"""
    try:
        if os.path.exists(index_path):
            return faiss.read_index(index_path)
        return None
    except Exception as e:
        logger.error(f"Error loading FAISS index: {e}")
        return None

def get_faiss_stats():
    """Get statistics about the FAISS index"""
    try:
        # Get index size
        index_size_bytes = get_index_size_bytes(FAISS_INDEX_PATH)
        index_size = format_size(index_size_bytes)
        
        # Load ID mapping
        id_mapping = load_id_mapping(FAISS_MAPPING_PATH)
        vector_count = len(id_mapping) if id_mapping else 0
        
        # Load FAISS index
        index = load_faiss_index(FAISS_INDEX_PATH)
        
        if index:
            index_type = type(index).__name__
            vector_dimension = index.d
            
            # Additional index-specific information
            if hasattr(index, 'ntotal'):
                total_vectors = index.ntotal
            else:
                total_vectors = vector_count
            
            # Check if index is trained (for certain index types)
            is_trained = "Yes" if hasattr(index, 'is_trained') and index.is_trained else "N/A"
            
            stats = {
                "index_exists": True,
                "index_type": index_type,
                "vector_dimension": vector_dimension,
                "total_vectors": total_vectors,
                "index_size": index_size,
                "index_size_bytes": index_size_bytes,
                "is_trained": is_trained
            }
        else:
            # Default stats if index doesn't exist
            stats = {
                "index_exists": False,
                "index_type": "Not found",
                "vector_dimension": FAISS_DIMENSION,
                "total_vectors": 0,
                "index_size": "0 B",
                "index_size_bytes": 0,
                "is_trained": "N/A"
            }
        
        return stats
    except Exception as e:
        logger.error(f"Error getting FAISS stats: {e}")
        return {
            "index_exists": False,
            "error": str(e),
            "index_type": "Error",
            "vector_dimension": FAISS_DIMENSION,
            "total_vectors": 0,
            "index_size": "0 B",
            "index_size_bytes": 0,
            "is_trained": "N/A"
        }

def get_sample_vectors(count=3):
    """Get a sample of vectors from the FAISS index"""
    try:
        index = load_faiss_index(FAISS_INDEX_PATH)
        id_mapping = load_id_mapping(FAISS_MAPPING_PATH)
        
        if not index or not id_mapping:
            return []
        
        # Get total number of vectors
        total_vectors = min(len(id_mapping), index.ntotal if hasattr(index, 'ntotal') else 0)
        
        if total_vectors == 0:
            return []
        
        # Sample a few vector IDs
        sample_count = min(count, total_vectors)
        if sample_count == 0:
            return []
            
        # Convert id_mapping keys to list to enable indexing
        mapping_keys = list(id_mapping.keys())
        sample_indices = np.random.choice(len(mapping_keys), sample_count, replace=False)
        
        samples = []
        for idx in sample_indices:
            key = mapping_keys[idx]
            faiss_idx = id_mapping[key]
            if isinstance(faiss_idx, int):
                internal_id = faiss_idx
                samples.append({
                    "id": key,
                    "internal_id": internal_id
                })
        
        return samples
    except Exception as e:
        logger.error(f"Error getting sample vectors: {e}")
        return []

def search_similar_vector(query_id, top_k=5):
    """Search for vectors similar to the given query vector"""
    try:
        index = load_faiss_index(FAISS_INDEX_PATH)
        id_mapping = load_id_mapping(FAISS_MAPPING_PATH)
        
        if not index or not id_mapping or query_id not in id_mapping:
            return []
            
        # We need to reconstruct the vector from the index
        query_idx = id_mapping[query_id]
        
        # This is tricky as not all FAISS indices support reconstruction
        # Only indices with IDMap or with .reconstruct() support this
        try:
            if hasattr(index, 'reconstruct'):
                query_vector = index.reconstruct(query_idx)
            else:
                logger.warning("Index doesn't support vector reconstruction")
                return []
                
            # Search similar vectors
            D, I = index.search(np.array([query_vector]), top_k)
            
            # Map internal IDs back to external IDs
            reverse_mapping = {v: k for k, v in id_mapping.items()}
            
            results = []
            for i in range(len(I[0])):
                internal_id = I[0][i]
                distance = D[0][i]
                
                if internal_id in reverse_mapping:
                    results.append({
                        "id": reverse_mapping[internal_id],
                        "internal_id": internal_id,
                        "distance": float(distance)
                    })
            
            return results
        except Exception as e:
            logger.error(f"Error during vector search: {e}")
            return []
    except Exception as e:
        logger.error(f"Error searching similar vectors: {e}")
        return []

def main():
    """Main function"""
    try:
        print("\n=== FAISS Vector Database Information ===\n")
        
        # Get FAISS statistics
        stats = get_faiss_stats()
        
        # Display stats
        print(f"Index exists: {stats['index_exists']}")
        if not stats['index_exists']:
            print(f"Error: {stats.get('error', 'Index file not found')}")
            print(f"\nDefault dimension: {stats['vector_dimension']}")
            print(f"Index path: {FAISS_INDEX_PATH}")
            print(f"ID mapping path: {FAISS_MAPPING_PATH}")
            return 1
            
        print(f"Index type: {stats['index_type']}")
        print(f"Vector dimension: {stats['vector_dimension']}")
        print(f"Total vectors: {stats['total_vectors']}")
        print(f"Index size: {stats['index_size']}")
        print(f"Trained: {stats['is_trained']}")
        
        # Get sample vectors
        samples = get_sample_vectors()
        
        if samples:
            print("\n=== Sample Vectors ===\n")
            for i, sample in enumerate(samples, 1):
                print(f"Vector {i}:")
                print(f"  External ID: {sample['id']}")
                print(f"  Internal ID: {sample['internal_id']}")
                
                # Try to find similar vectors
                similar = search_similar_vector(sample['id'])
                if similar and len(similar) > 1:
                    print("  Similar vectors:")
                    for j, sim in enumerate(similar[1:], 1):  # Skip the first one (itself)
                        print(f"    {j}. ID: {sim['id']}, Distance: {sim['distance']:.4f}")
                        
                print("")
        
        print("\nTo use these values in the RAG Vector Database tab, update your code to call:")
        print("vector_service.get_stats() which should return:")
        print(json.dumps(stats, indent=2))
        
        return 0
    except Exception as e:
        logger.error(f"Error in main function: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())